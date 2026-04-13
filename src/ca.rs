use crate::utils::{
    create_metadata_from_cert, generate_random_password, generate_unique_serial,
    git_add_and_commit, update_global_metadata, write_file, CertType, KeyAlgorithm,
};
use anyhow::Result;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::fs;
use std::path::Path;
use tracing::debug;

pub async fn init_root_ca(
    context: &Path,
    domain: &str,
    cn: &str,
    country: &str,
    key_algorithm: KeyAlgorithm,
    expiration_days: Option<u32>,
) -> Result<()> {
    debug!("Initializing root CA for domain: {}", domain);

    // Create directory structure: <domain>/
    let ca_dir = context.join(domain);

    // Define all file paths
    let key_path = ca_dir.join("key.pem");
    let crt_path = ca_dir.join("crt.pem");
    let _csr_path = ca_dir.join("csr.pem");
    let pass_path = ca_dir.join("key.pass");
    let ext_path = ca_dir.join("ext.ini");

    if ca_dir.exists() {
        println!("CA is already initialized, skip.");
        return Ok(());
    }

    println!("{} does not exist. will create", ca_dir.display());
    debug!("Creating CA directory: {:?}", ca_dir);
    fs::create_dir_all(&ca_dir)?;
    // Generate random password
    debug!("Generating random password");
    let password = generate_random_password()?;
    write_file(&pass_path, &password)?;

    let pkey = match key_algorithm {
        KeyAlgorithm::Rsa => {
            debug!(
                "openssl genrsa -aes128 -passout file:{} -out {} 4096",
                pass_path.display(),
                key_path.display()
            );
            debug!("Generating 4096-bit RSA private key");
            let rsa = Rsa::generate(4096)?;
            PKey::from_rsa(rsa)?
        }
        KeyAlgorithm::EcdsaP256 => {
            debug!(
                "openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -v2 aes-128-cbc -passout file:{} -out {}",
                pass_path.display(),
                key_path.display()
            );
            debug!("Generating ECDSA P-256 private key");
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)?
        }
    };
    let cipher = Cipher::aes_128_cbc();
    let key_pem = pkey.private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())?;
    fs::write(&key_path, &key_pem)?;

    // Build X509 Name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, country)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, cn)?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let name = name_builder.build();

    // Build X509 Certificate
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let days = expiration_days.unwrap_or(7300); // Default 20 years
    let not_after = Asn1Time::days_from_now(days.into())?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Add extensions
    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;
    let key_usage = KeyUsage::new().key_cert_sign().crl_sign().build()?;
    builder.append_extension(key_usage)?;
    let subject_key_id = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_key_id)?;
    let authority_key_id = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(authority_key_id)?;

    // Sign
    let serial = generate_unique_serial(context)?;
    builder.set_serial_number(&serial)?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();
    let cert_pem = cert.to_pem()?;
    let cert_pem_str = String::from_utf8(cert_pem)?;
    write_file(&crt_path, &cert_pem_str)?;

    // Create ext.ini file for CA
    let ext_content = format!(
        r#"[ ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical, permitted;DNS:.{}
"#,
        domain
    );
    write_file(&ext_path, &ext_content)?;

    // Write metadata for Root CA (global)
    let ca_cert = X509::from_pem(cert_pem_str.as_bytes())?;
    let mut metadata = create_metadata_from_cert(&ca_dir, &ca_cert, CertType::RootCa, None)?;
    metadata.key_algorithm = Some(key_algorithm);
    update_global_metadata(context, metadata)?;

    // Auto-commit to git
    let commit_msg = format!("Add root CA: {}", domain);
    if let Err(e) = git_add_and_commit(context, &commit_msg) {
        tracing::debug!("Git commit failed (non-fatal): {}", e);
    }

    // Display certificate details
    debug!(
        "CA Certificate for {} is written to {}",
        domain,
        crt_path.display()
    );
    println!(
        "CA Certificate for {} is written to {}",
        domain,
        crt_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_init_root_ca_success() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = init_root_ca(
            context,
            "test.com",
            "Test CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await;
        assert!(result.is_ok());

        assert!(context.join("test.com").exists());
        assert!(context.join("test.com").join("crt.pem").exists());
        assert!(context.join("test.com").join("key.pem").exists());
        assert!(context.join("meta.json").exists());
    }

    #[tokio::test]
    async fn test_init_root_ca_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        init_root_ca(
            context,
            "test.com",
            "Test CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await
        .unwrap();

        let result = init_root_ca(
            context,
            "test.com",
            "Test CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            None,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_root_ca_with_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = init_root_ca(
            context,
            "test.com",
            "Test CA",
            "CN",
            KeyAlgorithm::EcdsaP256,
            Some(365),
        )
        .await;
        assert!(result.is_ok());
    }
}
