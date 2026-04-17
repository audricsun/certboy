use crate::utils::{
    build_x509_name, create_metadata_from_cert, generate_random_password, generate_unique_serial,
    get_from_global_metadata, git_add_and_commit, update_global_metadata, write_file,
    CertificateType, KeyAlgorithm,
};
use anyhow::Result;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509ReqBuilder, X509};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::debug;

struct CaContext<'a> {
    cert_pem: &'a [u8],
    key_pem: &'a [u8],
    password: &'a str,
}

fn generate_ica_objects(
    cn: &str,
    country: &str,
    key_algorithm: KeyAlgorithm,
    expiration_days: Option<u32>,
    ica_password: &str,
    serial_bytes: &[u8],
    ca: CaContext<'_>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let pkey = match key_algorithm {
        KeyAlgorithm::Rsa => {
            debug!("Generating 4096-bit RSA private key for ICA");
            let rsa = Rsa::generate(4096)?;
            PKey::from_rsa(rsa)?
        }
        KeyAlgorithm::EcdsaP256 => {
            debug!("Generating ECDSA P-256 private key for ICA");
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)?
        }
    };

    let cipher = Cipher::aes_256_cbc();
    let key_pem = pkey.private_key_to_pem_pkcs8_passphrase(cipher, ica_password.as_bytes())?;

    let name = build_x509_name(country, cn, cn)?;

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(&pkey)?;
    req_builder.sign(&pkey, MessageDigest::sha256())?;
    let csr = req_builder.build();
    let csr_pem = csr.to_pem()?;

    let ca_cert = X509::from_pem(ca.cert_pem)?;
    let ca_key = PKey::private_key_from_pem_passphrase(ca.key_pem, ca.password.trim().as_bytes())?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let days = expiration_days.unwrap_or(3650);
    let not_after = Asn1Time::days_from_now(days)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let basic_constraints = BasicConstraints::new().ca().pathlen(0).build()?;
    builder.append_extension(basic_constraints)?;
    let key_usage = KeyUsage::new().key_cert_sign().crl_sign().build()?;
    builder.append_extension(key_usage)?;
    let subject_key_id =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(&ca_cert), None))?;
    builder.append_extension(subject_key_id)?;
    let authority_key_id = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(&ca_cert), None))?;
    builder.append_extension(authority_key_id)?;

    let bn = openssl::bn::BigNum::from_slice(serial_bytes)?;
    let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&bn)?;
    builder.set_serial_number(&serial_asn1)?;
    builder.sign(&ca_key, MessageDigest::sha256())?;
    let ica_cert = builder.build();
    let cert_pem = ica_cert.to_pem()?;

    Ok((key_pem, csr_pem, cert_pem))
}

pub async fn sign_ica(
    context: &Path,
    domain: &str,
    ca_domain: &str,
    cn: &str,
    country: &str,
    expiration_days: Option<u32>,
) -> Result<()> {
    debug!(
        "Signing intermediate CA for domain: {} with root CA: {}",
        domain, ca_domain
    );

    let root_ca_dir = context.join(ca_domain);
    let root_ca_key = root_ca_dir.join("key.pem");
    let root_ca_crt = root_ca_dir.join("crt.pem");
    let root_ca_pass = root_ca_dir.join("key.pass");

    let ica_dir = root_ca_dir.join("intermediates.d").join(domain);
    let ica_key = ica_dir.join("key.pem");
    let ica_crt = ica_dir.join("crt.pem");
    let ica_csr = ica_dir.join("csr.pem");
    let ica_pass = ica_dir.join("key.pass");
    let ica_ext = ica_dir.join("ext.cnf");

    if !root_ca_dir.exists() {
        return Err(anyhow::anyhow!(
            "Root CA: {} directory: {} not found... will exit",
            ca_domain,
            root_ca_dir.display()
        ));
    }

    let ca_cert_pem = fs::read(&root_ca_crt)?;
    let ca_cert = X509::from_pem(&ca_cert_pem)?;
    let ca_not_after = ca_cert.not_after().to_owned();
    let key_algorithm = get_from_global_metadata(context, ca_domain)
        .ok()
        .flatten()
        .and_then(|m| m.key_algorithm)
        .or_else(|| match ca_cert.public_key().ok()?.id() {
            Id::RSA => Some(KeyAlgorithm::Rsa),
            Id::EC => Some(KeyAlgorithm::EcdsaP256),
            _ => None,
        })
        .unwrap_or(KeyAlgorithm::EcdsaP256);

    let two_weeks = Asn1Time::days_from_now(14)?;
    if ca_not_after < two_weeks {
        eprintln!("[ERROR] Parent CA certificate will expire in 2 weeks, please renew CA certificate first!");
        return Err(anyhow::anyhow!("CA certificate is about to expire"));
    }

    if ica_dir.exists() && ica_crt.exists() {
        let ica_cert_pem = fs::read(&ica_crt)?;
        let ica_cert = X509::from_pem(&ica_cert_pem)?;
        let ica_not_after = ica_cert.not_after().to_owned();
        if ica_not_after < two_weeks {
            println!("ICA certificate will expire in 2 weeks, automatically re-signing...");
        } else {
            println!("ICA already exists with sufficient validity, skipping.");
            return Ok(());
        }
    }

    println!("{} does not exist. will create", ica_dir.display());
    debug!("Creating ICA directory: {:?}", ica_dir);
    fs::create_dir_all(&ica_dir)?;

    let password = generate_random_password()?;
    write_file(&ica_pass, &password)?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&ica_pass)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&ica_pass, perms)?;
    }

    let ca_cert_pem = fs::read(&root_ca_crt)?;
    let ca_key_pem = fs::read(&root_ca_key)?;
    let ca_pass_content = fs::read_to_string(&root_ca_pass)?;
    let serial = generate_unique_serial(context)?;
    let serial_bytes = serial.to_bn()?.to_vec();

    let (key_pem, csr_pem, cert_pem) = tokio::task::spawn_blocking({
        let cn = cn.to_string();
        let country = country.to_string();
        let ca_cert_pem = ca_cert_pem.clone();
        let ca_key_pem = ca_key_pem.clone();
        let ca_pass_content = ca_pass_content.clone();
        let serial_bytes = serial_bytes.clone();
        move || {
            generate_ica_objects(
                &cn,
                &country,
                key_algorithm,
                expiration_days,
                &password,
                &serial_bytes,
                CaContext {
                    cert_pem: &ca_cert_pem,
                    key_pem: &ca_key_pem,
                    password: &ca_pass_content,
                },
            )
        }
    })
    .await??;

    fs::write(&ica_key, &key_pem)?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&ica_key)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&ica_key, perms)?;
    }

    fs::write(&ica_csr, &csr_pem)?;
    fs::write(&ica_crt, &cert_pem)?;

    let ica_cert = X509::from_pem(&cert_pem)?;

    let ext_content = format!(
        r#"[ intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:true, pathlen:0
nameConstraints = critical, permitted;DNS:.{}
"#,
        domain
    );
    write_file(&ica_ext, &ext_content)?;

    // Write metadata for ICA with parent reference
    let mut metadata = create_metadata_from_cert(
        &ica_dir,
        &ica_cert,
        CertificateType::Ica,
        Some(ca_domain.to_string()),
    )?;
    metadata.key_algorithm = Some(key_algorithm);
    update_global_metadata(context, metadata)?;

    let commit_msg = format!("Add ICA: {} (signed by {})", domain, ca_domain);
    if let Err(e) = git_add_and_commit(context, &commit_msg) {
        tracing::debug!("Git commit failed (non-fatal): {}", e);
    }

    println!("ICA Certificate created:");
    println!("  Certificate: {}", ica_crt.display());
    println!("  Private Key: {}", ica_key.display());
    println!("  Key Password: {}", ica_pass.display());
    println!("  Extension file: {}", ica_ext.display());

    debug!("ICA signing completed successfully for {}", domain);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::init_root_ca;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_sign_ica_success() {
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

        let result = sign_ica(context, "ica.com", "root.com", "ICA Test", "CN", None).await;
        assert!(result.is_ok());

        assert!(context
            .join("root.com")
            .join("intermediates.d")
            .join("ica.com")
            .exists());
    }

    #[tokio::test]
    async fn test_sign_ica_already_exists() {
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

        sign_ica(context, "ica.com", "root.com", "ICA Test", "CN", None)
            .await
            .unwrap();

        let result = sign_ica(context, "ica.com", "root.com", "ICA Test", "CN", None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_ica_root_ca_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = sign_ica(
            context,
            "ica.com",
            "nonexistent.com",
            "ICA Test",
            "CN",
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_ica_with_expiration() {
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

        let result = sign_ica(context, "ica.com", "root.com", "ICA Test", "CN", Some(365)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_ica_different_country() {
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

        let result = sign_ica(context, "ica.com", "root.com", "ICA Test", "US", None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_ica_subdomain() {
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

        let result = sign_ica(context, "sub.root.com", "root.com", "Sub ICA", "CN", None).await;
        assert!(result.is_ok());
    }
}
