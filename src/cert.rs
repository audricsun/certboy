use anyhow::Result;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509ReqBuilder, X509};
use tracing::debug;

use crate::utils::{
    create_metadata_from_cert, generate_default_ext_content, generate_random_password,
    generate_unique_serial, get_from_global_metadata, git_add_and_commit, has_metadata,
    parse_alt_names_from_ext, read_file, read_metadata, update_global_metadata, write_file,
    CertType, KeyAlgorithm,
};
use openssl::pkcs12::Pkcs12;
use std::fs;
use std::path::Path;

pub async fn sign_cert(
    context: &Path,
    domain: &str,
    ca_domain: &str,
    force: bool,
    altnames: Option<&[String]>,
    expiration_days: Option<u32>,
    encrypt_key: bool,
) -> Result<()> {
    debug!(
        "Signing certificate for domain: {} with CA: {}",
        domain, ca_domain
    );

    // First check if CA exists - could be root CA or ICA
    // Try metadata-based detection first, then search through all directories

    // First try direct paths (Root CA or ICA with same name)
    let direct_paths = [
        context.join(ca_domain), // Root CA at context/<domain>
        context
            .join(ca_domain)
            .join("intermediates.d")
            .join(ca_domain), // ICA at context/<domain>/intermediates.d/<domain>
    ];

    let mut ca_dir = None;
    let mut _ca_type = "root";

    // Try direct paths first
    for path in direct_paths {
        if path.exists() && path.join("crt.pem").exists() {
            ca_dir = Some(path.clone());
            if path.to_string_lossy().contains("intermediates.d") {
                _ca_type = "ica";
            }
            break;
        }
    }

    // If not found, search through all intermediates.d in all root CAs
    if ca_dir.is_none() {
        if let Ok(entries) = fs::read_dir(context) {
            for entry in entries.flatten() {
                let root_path = entry.path();
                if root_path.is_dir() {
                    let ica_path = root_path.join("intermediates.d").join(ca_domain);
                    if ica_path.exists() && ica_path.join("crt.pem").exists() {
                        ca_dir = Some(ica_path.clone());
                        _ca_type = "ica";
                        debug!(
                            "Found ICA {} in intermediates.d of {}",
                            ca_domain,
                            root_path.display()
                        );
                        break;
                    }
                }
            }
        }
    }

    if ca_dir.is_none() {
        return Err(anyhow::anyhow!(
            "CA: {} not found in context {}",
            ca_domain,
            context.display()
        ));
    }

    let ca_dir = ca_dir.unwrap();

    // Try to read metadata for accurate type detection
    if has_metadata(&ca_dir) {
        if let Ok(meta) = read_metadata(&ca_dir) {
            match meta.cert_type {
                CertType::Ica => {
                    _ca_type = "ica";
                    debug!("Detected ICA as signing CA: {}", meta.domain);
                }
                CertType::RootCa => {
                    _ca_type = "root";
                    debug!("Detected Root CA as signing CA: {}", meta.domain);
                }
                _ => {}
            }
        }
    }

    // ICA domain validation: ICA can only sign certificates for domains it owns
    // e.g., ops.example.io ICA can only sign *.ops.example.io
    if _ca_type == "ica" {
        let ica_domain = ca_domain;
        if !domain.ends_with(&format!(".{}", ica_domain)) && domain != ica_domain {
            return Err(anyhow::anyhow!(
                "Domain '{}' is not owned by ICA '{}'. ICA can only sign certificates for domains under '{}' (e.g., subdomain.{})",
                domain, ica_domain, ica_domain, ica_domain
            ));
        }
        debug!(
            "Domain '{}' validated as owned by ICA '{}'",
            domain, ica_domain
        );
    }

    let ca_key = ca_dir.join("key.pem");
    let ca_crt = ca_dir.join("crt.pem");
    let ca_pass = ca_dir.join("key.pass");

    let cert_dir = ca_dir.join("certificates.d").join(domain);
    let cert_key = cert_dir.join("key.pem");
    let cert_crt = cert_dir.join("crt.pem");
    let cert_csr = cert_dir.join("csr.pem");
    let cert_pass = cert_dir.join("pass.key");
    let cert_ext = cert_dir.join("ext.cnf");
    let cert_fullchain = cert_dir.join("fullchain.crt");
    let cert_p12 = cert_dir.join("cert.p12");

    // Check certificate expiry if exists
    if cert_dir.exists() && cert_crt.exists() && !force {
        let cert_pem = fs::read(&cert_crt)?;
        let cert = X509::from_pem(&cert_pem)?;
        let not_after = cert.not_after().to_owned();
        let one_week = Asn1Time::days_from_now(7)?;

        if not_after < one_week {
            println!("Certificate will expire in a week, re-signing...");
        } else {
            println!("Certificate already exists with sufficient validity, skipping.");
            return Ok(());
        }
    }

    println!("{} does not exist. will create", cert_dir.display());
    debug!("Creating certificate directory: {:?}", cert_dir);
    fs::create_dir_all(&cert_dir)?;

    // Generate password
    let password = generate_random_password()?;
    write_file(&cert_pass, &password)?;

    let ca_cert_pem_for_algo = fs::read(&ca_crt)?;
    let ca_cert_for_algo = X509::from_pem(&ca_cert_pem_for_algo)?;
    let key_algorithm = get_from_global_metadata(context, ca_domain)
        .ok()
        .flatten()
        .and_then(|m| m.key_algorithm)
        .or_else(|| match ca_cert_for_algo.public_key().ok()?.id() {
            Id::RSA => Some(KeyAlgorithm::Rsa),
            Id::EC => Some(KeyAlgorithm::EcdsaP256),
            _ => None,
        })
        .unwrap_or(KeyAlgorithm::EcdsaP256);

    let pkey = match key_algorithm {
        KeyAlgorithm::Rsa => {
            debug!("Generating 2048-bit RSA private key");
            let rsa = Rsa::generate(2048)?;
            PKey::from_rsa(rsa)?
        }
        KeyAlgorithm::EcdsaP256 => {
            debug!("Generating ECDSA P-256 private key");
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)?
        }
    };
    let key_pem = if encrypt_key {
        let cipher = Cipher::aes_256_cbc();
        pkey.private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())?
    } else {
        pkey.private_key_to_pem_pkcs8()?
    };
    fs::write(&cert_key, &key_pem)?;

    // Build certificate X509 Name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "CN")?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, domain)?;
    let name = name_builder.build();

    // Build CSR
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(&pkey)?;
    req_builder.sign(&pkey, MessageDigest::sha256())?;
    let csr = req_builder.build();
    let csr_pem = csr.to_pem()?;
    fs::write(&cert_csr, &csr_pem)?;

    // Load CA cert and key
    let ca_cert_pem = fs::read(&ca_crt)?;
    let ca_key_pem = fs::read(&ca_key)?;
    let ca_pass_content = fs::read_to_string(&ca_pass)?;
    let ca_cert = X509::from_pem(&ca_cert_pem)?;
    let ca_key =
        PKey::private_key_from_pem_passphrase(&ca_key_pem, ca_pass_content.trim().as_bytes())?;

    // Create or read ext.cnf file
    let ext_content = if cert_ext.exists() {
        read_file(&cert_ext)?
    } else {
        generate_default_ext_content(domain)
    };

    // Parse alt names from ext.cnf or command line
    let parsed_altnames = parse_alt_names_from_ext(&ext_content)?;
    let final_altnames = if let Some(cmd_altnames) = altnames {
        cmd_altnames.to_vec()
    } else {
        parsed_altnames
    };

    // Update ext.cnf with all alt names
    let updated_ext_content = generate_ext_content_with_altnames(domain, &final_altnames);
    write_file(&cert_ext, &updated_ext_content)?;

    // Build certificate
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let days = expiration_days.unwrap_or(1095); // Default 3 years
    let not_after = Asn1Time::days_from_now(days)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Add extensions
    let basic_constraints = BasicConstraints::new().critical().build()?;
    builder.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()?;
    builder.append_extension(key_usage)?;

    let extended_key_usage = ExtendedKeyUsage::new().server_auth().build()?;
    builder.append_extension(extended_key_usage)?;

    let subject_key_id =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(&ca_cert), None))?;
    builder.append_extension(subject_key_id)?;

    let authority_key_id = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(&ca_cert), None))?;
    builder.append_extension(authority_key_id)?;

    // Add Subject Alternative Names if present
    // Note: we need to add domain explicitly since final_altnames may contain it
    let mut san_builder = SubjectAlternativeName::new();
    san_builder.dns(domain);
    for altname in &final_altnames {
        // Skip if same as main domain (already added)
        if altname == domain {
            continue;
        }
        if let Ok(ip) = altname.parse::<std::net::IpAddr>() {
            san_builder.ip(&ip.to_string());
        } else {
            san_builder.dns(altname);
        }
    }
    let subject_alt_name = san_builder.build(&builder.x509v3_context(Some(&ca_cert), None))?;
    builder.append_extension(subject_alt_name)?;

    // Sign certificate with CA
    let serial = generate_unique_serial(context)?;
    builder.set_serial_number(&serial)?;
    builder.sign(&ca_key, MessageDigest::sha256())?;
    let cert = builder.build();
    let cert_pem = cert.to_pem()?;
    fs::write(&cert_crt, &cert_pem)?;

    // Fullchain: only needed for ICA-signed certificates
    // Contains: server cert + ICA cert (no root CA)
    // This allows TLS clients to verify the chain without needing the root CA
    let fullchain_created = if _ca_type == "ica" {
        let mut fullchain_content = cert_pem.clone();
        fullchain_content.extend_from_slice(&ca_cert_pem);
        fs::write(&cert_fullchain, &fullchain_content)?;
        true
    } else {
        false
    };

    // Generate P12 file
    let p12_password = generate_random_password()?;
    let p12 = Pkcs12::builder()
        .name(domain)
        .pkey(&pkey)
        .cert(&cert)
        .build2(&p12_password)?;
    let p12_bytes = p12.to_der()?;
    fs::write(&cert_p12, &p12_bytes)?;
    write_file(&cert_dir.join("p12.pass"), &p12_password)?;

    // Write metadata for TLS certificate with parent (signing CA) reference
    let mut metadata =
        create_metadata_from_cert(&cert_dir, &cert, CertType::Tls, Some(ca_domain.to_string()))?;
    metadata.private_key_encrypted = Some(encrypt_key);
    metadata.private_key_password_file = Some("pass.key".to_string());
    metadata.key_algorithm = Some(key_algorithm);
    update_global_metadata(context, metadata)?;

    let commit_msg = format!("Add TLS cert: {} (signed by {})", domain, ca_domain);
    if let Err(e) = git_add_and_commit(context, &commit_msg) {
        tracing::debug!("Git commit failed (non-fatal): {}", e);
    }

    println!("Certificate created:");
    println!("  Certificate: {}", cert_crt.display());
    println!("  Private Key: {}", cert_key.display());
    println!("  Key Password File: {}", cert_pass.display());
    println!("  Extension file: {}", cert_ext.display());
    if fullchain_created {
        println!("  Fullchain: {}", cert_fullchain.display());
    }
    println!("  P12 file: {}", cert_p12.display());
    println!("  P12 Password: {}", cert_dir.join("p12.pass").display());

    debug!("Certificate signing completed successfully for {}", domain);
    Ok(())
}

fn generate_ext_content_with_altnames(domain: &str, altnames: &[String]) -> String {
    let mut config = String::new();

    // Add main domain as first entry
    config.push_str(&format!("DNS.1 = {}\n", domain));

    // Add altnames, skipping duplicates (including the main domain)
    let mut index = 2;
    for altname in altnames {
        // Skip if this altname equals the main domain (already added as DNS.1)
        if altname == domain {
            continue;
        }

        if altname.parse::<std::net::IpAddr>().is_ok() {
            config.push_str(&format!("IP.{} = {}\n", index, altname));
        } else {
            config.push_str(&format!("DNS.{} = {}\n", index, altname));
        }
        index += 1;
    }

    format!(
        r#"basicConstraints        = critical,CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer:always
nsCertType              = server
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth
subjectAltName          = @alt_names
[alt_names]
{config}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::init_root_ca;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_sign_cert_with_root_ca() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        init_root_ca(
            context,
            "root.com",
            "Root CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await
        .unwrap();

        let result = sign_cert(context, "server.com", "root.com", false, None, None, false).await;
        assert!(result.is_ok());

        assert!(context
            .join("root.com")
            .join("certificates.d")
            .join("server.com")
            .exists());
    }

    #[tokio::test]
    async fn test_sign_cert_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        init_root_ca(
            context,
            "root.com",
            "Root CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await
        .unwrap();

        sign_cert(context, "server.com", "root.com", false, None, None, false)
            .await
            .unwrap();

        let result = sign_cert(context, "server.com", "root.com", false, None, None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_cert_force_renew() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        init_root_ca(
            context,
            "root.com",
            "Root CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await
        .unwrap();

        sign_cert(context, "server.com", "root.com", false, None, None, false)
            .await
            .unwrap();

        let result = sign_cert(context, "server.com", "root.com", true, None, None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_cert_with_altnames() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        init_root_ca(
            context,
            "root.com",
            "Root CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await
        .unwrap();

        let altnames = vec!["www.server.com".to_string(), "api.server.com".to_string()];
        let result = sign_cert(
            context,
            "server.com",
            "root.com",
            false,
            Some(&altnames),
            None,
            false,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_cert_ca_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = sign_cert(
            context,
            "server.com",
            "nonexistent.com",
            false,
            None,
            None,
            false,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_cert_with_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        init_root_ca(
            context,
            "root.com",
            "Root CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await
        .unwrap();

        let result = sign_cert(
            context,
            "server.com",
            "root.com",
            false,
            None,
            Some(180),
            false,
        )
        .await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_ext_content_with_altnames() {
        let altnames = vec!["www.example.com".to_string(), "api.example.com".to_string()];
        let content = generate_ext_content_with_altnames("example.com", &altnames);

        assert!(content.contains("DNS.1 = example.com"));
        assert!(content.contains("DNS.2 = www.example.com"));
        assert!(content.contains("DNS.3 = api.example.com"));
    }

    #[test]
    fn test_generate_ext_content_with_ip() {
        let altnames = vec!["127.0.0.1".to_string()];
        let content = generate_ext_content_with_altnames("example.com", &altnames);

        assert!(content.contains("DNS.1 = example.com"));
        assert!(content.contains("IP.2 = 127.0.0.1"));
    }

    #[test]
    fn test_generate_ext_content_duplicate_domain() {
        let altnames = vec!["example.com".to_string()];
        let content = generate_ext_content_with_altnames("example.com", &altnames);

        assert!(content.contains("DNS.1 = example.com"));
        assert!(!content.contains("DNS.2"));
    }

    #[test]
    fn test_generate_ext_content_empty_altnames() {
        let altnames: Vec<String> = vec![];
        let content = generate_ext_content_with_altnames("example.com", &altnames);

        assert!(content.contains("DNS.1 = example.com"));
        assert!(content.contains("subjectAltName"));
    }

    #[test]
    fn test_generate_ext_content_wildcard() {
        let altnames = vec!["*.example.com".to_string()];
        let content = generate_ext_content_with_altnames("example.com", &altnames);

        assert!(content.contains("DNS.1 = example.com"));
        assert!(content.contains("DNS.2 = *.example.com"));
    }

    #[test]
    fn test_generate_ext_content_mixed() {
        let altnames = vec![
            "www.example.com".to_string(),
            "127.0.0.1".to_string(),
            "*.example.com".to_string(),
        ];
        let content = generate_ext_content_with_altnames("example.com", &altnames);

        assert!(content.contains("DNS.1 = example.com"));
        assert!(content.contains("DNS.2 = www.example.com"));
        assert!(content.contains("IP.3 = 127.0.0.1"));
        assert!(content.contains("DNS.4 = *.example.com"));
    }
}
