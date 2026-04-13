use crate::utils::{
    create_metadata_from_cert, generate_random_password, generate_unique_serial,
    get_from_global_metadata, git_add_and_commit, update_global_metadata, write_file, CertType,
    KeyAlgorithm,
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
use openssl::x509::{X509Builder, X509NameBuilder, X509ReqBuilder, X509};
use std::fs;
use std::path::Path;
use tracing::debug;

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

    let pkey = match key_algorithm {
        KeyAlgorithm::Rsa => {
            debug!(
                "openssl genrsa -aes256 -passout file:{} -out {} 4096",
                ica_pass.display(),
                ica_key.display()
            );
            debug!("Generating 4096-bit RSA private key for ICA");
            let rsa = Rsa::generate(4096)?;
            PKey::from_rsa(rsa)?
        }
        KeyAlgorithm::EcdsaP256 => {
            debug!(
                "openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -v2 aes-256-cbc -passout file:{} -out {}",
                ica_pass.display(),
                ica_key.display()
            );
            debug!("Generating ECDSA P-256 private key for ICA");
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)?
        }
    };
    let cipher = Cipher::aes_256_cbc();
    let key_pem = pkey.private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())?;
    fs::write(&ica_key, &key_pem)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, country)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, cn)?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let name = name_builder.build();

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(&pkey)?;
    req_builder.sign(&pkey, MessageDigest::sha256())?;
    let csr = req_builder.build();
    let csr_pem = csr.to_pem()?;
    fs::write(&ica_csr, &csr_pem)?;

    let ca_cert_pem = fs::read(&root_ca_crt)?;
    let ca_key_pem = fs::read(&root_ca_key)?;
    let ca_pass_content = fs::read_to_string(&root_ca_pass)?;
    let ca_cert = X509::from_pem(&ca_cert_pem)?;
    let ca_key =
        PKey::private_key_from_pem_passphrase(&ca_key_pem, ca_pass_content.trim().as_bytes())?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let days = expiration_days.unwrap_or(3650); // Default 10 years
    let not_after = Asn1Time::days_from_now(days.into())?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

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

    let serial = generate_unique_serial(context)?;
    builder.set_serial_number(&serial)?;
    builder.sign(&ca_key, MessageDigest::sha256())?;
    let ica_cert = builder.build();
    let ica_cert_pem = ica_cert.to_pem()?;
    fs::write(&ica_crt, &ica_cert_pem)?;

    // Write metadata for ICA with parent reference
    let mut metadata = create_metadata_from_cert(
        &ica_dir,
        &ica_cert,
        CertType::Ica,
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
