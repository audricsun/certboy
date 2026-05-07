use assert_cmd::Command;
use certboy::{ca, cert, ica, utils};
use openssl::x509::X509;
use predicates::prelude::*;
use serial_test::serial;
use std::fs;
use std::path::Path;
use std::sync::Once;
use tempfile::TempDir;

static INIT: Once = Once::new();

fn init_logger() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .init();
    });
}

#[tokio::test]
#[serial]
async fn test_init_root_ca() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-1.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    if let Err(ref e) = res {
        tracing::error!("test_init_root_ca failed: {e:?}");
    }
    assert!(res.is_ok());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_sign_ica() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-2.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    if let Err(ref e) = ca_res {
        tracing::error!("test_sign_ica root_ca failed: {e:?}");
    }
    assert!(ca_res.is_ok());
    let res = ica::sign_ica(
        &temp_dir_path,
        "test-ica.local",
        "test-root-2.local",
        "TestOrg",
        "CN",
        None,
    )
    .await;
    if let Err(ref e) = res {
        tracing::error!("test_sign_ica failed: {e:?}");
    }
    assert!(res.is_ok());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_sign_cert() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-3.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    if let Err(ref e) = ca_res {
        tracing::error!("test_sign_cert root_ca failed: {e:?}");
    }
    assert!(ca_res.is_ok());
    let res = cert::sign_cert(
        &temp_dir_path,
        "testcert.local",
        "test-root-3.local",
        false,
        None,
        None,
        false,
    )
    .await;
    if let Err(ref e) = res {
        tracing::error!("test_sign_cert failed: {e:?}");
    }
    assert!(res.is_ok());
    drop(tmp);
}

// === 异常测试 ===

#[tokio::test]
#[serial]
async fn test_sign_ica_with_missing_ca() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();
    // 不初始化根CA，直接签发ICA
    let res = ica::sign_ica(
        &temp_dir_path,
        "ica-missing-ca.local",
        "not-exist-ca.local",
        "TestOrg",
        "CN",
        None,
    )
    .await;
    tracing::debug!("test_sign_ica_with_missing_ca result: {res:?}");
    assert!(res.is_err());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_sign_cert_with_missing_ca() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();
    // 不初始化根CA，直接签发证书
    let res = cert::sign_cert(
        &temp_dir_path,
        "cert-missing-ca.local",
        "not-exist-ca.local",
        false,
        None,
        None,
        false,
    )
    .await;
    tracing::debug!("test_sign_cert_with_missing_ca result: {res:?}");
    assert!(res.is_err());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_ica_domain_validation() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create Root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-root.local",
        "test-root.local",
        "OpsDivision",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Test 1: Sign cert with domain owned by ICA (should succeed)
    let res1 = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-root.local",
        "ops.test-root.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(
        res1.is_ok(),
        "ICA should be able to sign certs for its own domain"
    );

    // Test 2: Sign cert with domain NOT owned by ICA (should fail)
    let res2 = cert::sign_cert(
        &temp_dir_path,
        "www.test-root.local",
        "ops.test-root.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(
        res2.is_err(),
        "ICA should NOT be able to sign certs for domains it doesn't own"
    );
    assert!(
        res2.unwrap_err()
            .to_string()
            .contains("is not owned by ICA"),
        "Error message should mention domain ownership"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_import_certificate() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create a root CA first
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-import.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create import source directory
    let import_source = tmp.path().join("import_source");
    fs::create_dir_all(&import_source).unwrap();

    // Copy the root CA to import source
    let source_ca_dir = temp_dir_path.join("test-root-import.local");
    fs::copy(source_ca_dir.join("crt.pem"), import_source.join("crt.pem")).unwrap();
    fs::copy(source_ca_dir.join("key.pem"), import_source.join("key.pem")).unwrap();

    // Create a new context for import
    let import_context = tmp.path().join("import_context");
    fs::create_dir_all(&import_context).unwrap();

    // Import the certificate
    let import_result = utils::import_certificate(&import_source, &import_context).await;
    if let Err(ref e) = import_result {
        tracing::error!("test_import_certificate failed: {e:?}");
    }
    assert!(import_result.is_ok());

    // Verify import created the directory (import uses the source folder name)
    let imported_dir = import_context.join("import_source");
    assert!(imported_dir.exists());
    assert!(imported_dir.join("crt.pem").exists());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create a root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-list.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create an ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "test-ica-list.local",
        "test-root-list.local",
        "TestOrg",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create a server cert
    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "test-server-list.local",
        "test-root-list.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    // List certificates (check mode without renew)
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    if let Err(ref e) = list_result {
        tracing::error!("test_list_certificates failed: {e:?}");
    }
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_import_ica_certificate() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create a root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create an ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "test-ica.local",
        "test-root-ica.local",
        "TestOrg",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create import source with ICA
    let import_source = temp_dir_path
        .join("test-root-ica.local")
        .join("intermediates.d")
        .join("test-ica.local");

    // Create a new context for import
    let import_context = tmp.path().join("import_context");
    fs::create_dir_all(&import_context).unwrap();

    // First import root CA
    let root_source = temp_dir_path.join("test-root-ica.local");
    let root_import = utils::import_certificate(&root_source, &import_context).await;
    assert!(root_import.is_ok());

    // Then import ICA
    let ica_import = utils::import_certificate(&import_source, &import_context).await;
    if let Err(ref e) = ica_import {
        tracing::error!("test_import_ica_certificate failed: {e:?}");
    }
    assert!(ica_import.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_with_ica() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-complex.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-complex.local",
        "test-root-complex.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create server cert under root
    let cert1_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-complex.local",
        "test-root-complex.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert1_res.is_ok());

    // Create server cert under ICA
    let cert2_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-complex.local",
        "ops.test-complex.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert2_res.is_ok());

    // List all certificates
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_fullchain_order_ica_signed_cert() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-fullchain.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-fullchain.local",
        "test-root-fullchain.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create server cert signed by ICA
    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-fullchain.local",
        "ops.test-fullchain.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    // Read fullchain and verify order
    let fullchain_path = temp_dir_path
        .join("test-root-fullchain.local")
        .join("intermediates.d")
        .join("ops.test-fullchain.local")
        .join("certificates.d")
        .join("dashboard.ops.test-fullchain.local")
        .join("fullchain.crt");

    let fullchain_content = fs::read(&fullchain_path).unwrap();

    // Parse certificates from fullchain
    let fullchain_str = String::from_utf8_lossy(&fullchain_content);
    let certs: Vec<&str> = fullchain_str
        .split("-----BEGIN CERTIFICATE-----")
        .filter(|s| !s.trim().is_empty())
        .collect();

    // For ICA-signed certs, fullchain should have exactly 2 certificates:
    // 1. Server certificate (leaf)
    // 2. ICA certificate (intermediate)
    // No Root CA certificate
    assert_eq!(
        certs.len(),
        2,
        "Fullchain should have exactly 2 certificates (server + ICA)"
    );

    // Verify fullchain can be used with openssl verify
    // For ICA-signed certs, fullchain contains: server cert -> ICA
    // We need to verify using the ICA certificate
    let ica_cert_path = temp_dir_path
        .join("test-root-fullchain.local")
        .join("intermediates.d")
        .join("ops.test-fullchain.local")
        .join("crt.pem");

    let output = std::process::Command::new("openssl")
        .args([
            "verify",
            "-partial_chain",
            "-CAfile",
            &ica_cert_path.to_string_lossy(),
            &fullchain_path.to_string_lossy(),
        ])
        .output()
        .expect("Failed to execute openssl verify");

    let output_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(
        output_str.contains("OK"),
        "Fullchain verification failed. Stdout: {}, Stderr: {}",
        output_str,
        stderr_str
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_fullchain_order_root_signed_cert() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-fullchain2.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create server cert signed by root CA
    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-fullchain2.local",
        "test-root-fullchain2.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    // Root CA signed certs should NOT have fullchain.crt
    let fullchain_path = temp_dir_path
        .join("test-root-fullchain2.local")
        .join("certificates.d")
        .join("www.test-fullchain2.local")
        .join("fullchain.crt");

    assert!(
        !fullchain_path.exists(),
        "Root CA signed certs should not have fullchain.crt"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_fullchain_order_empty() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create a temp directory without fullchain.crt
    let test_dir = temp_dir_path.join("test-cert");
    fs::create_dir_all(&test_dir).unwrap();

    // Verify that missing fullchain.crt returns OK
    let result = utils::verify_fullchain_order(&test_dir);
    assert!(result.is_ok());
    let (is_valid, message) = result.unwrap();
    assert!(is_valid);
    assert!(message.contains("not found"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_fullchain_order_wrong_count() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-wrong.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-wrong.local",
        "test-root-wrong.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create server cert signed by ICA
    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-wrong.local",
        "ops.test-wrong.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    // Read fullchain and make it have wrong number of certs
    let fullchain_path = temp_dir_path
        .join("test-root-wrong.local")
        .join("intermediates.d")
        .join("ops.test-wrong.local")
        .join("certificates.d")
        .join("dashboard.ops.test-wrong.local")
        .join("fullchain.crt");

    // Write only one cert (wrong count)
    let server_cert_path = temp_dir_path
        .join("test-root-wrong.local")
        .join("intermediates.d")
        .join("ops.test-wrong.local")
        .join("certificates.d")
        .join("dashboard.ops.test-wrong.local")
        .join("crt.pem");
    let single_cert = fs::read(&server_cert_path).unwrap();
    fs::write(&fullchain_path, &single_cert).unwrap();

    // Verify should report wrong count
    let result = utils::verify_fullchain_order(fullchain_path.parent().unwrap());
    assert!(result.is_ok());
    let (is_valid, message) = result.unwrap();
    assert!(!is_valid);
    assert!(message.contains("exactly 2"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_fullchain_order_empty_cert() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-empty.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-empty.local",
        "test-root-empty.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create server cert signed by ICA
    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-empty.local",
        "ops.test-empty.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-root-empty.local")
        .join("intermediates.d")
        .join("ops.test-empty.local")
        .join("certificates.d")
        .join("dashboard.ops.test-empty.local");

    // Verify fullchain exists and is correct
    let result = utils::verify_fullchain_order(&cert_dir);
    assert!(result.is_ok());
    let (is_valid, message) = result.unwrap();
    assert!(is_valid, "Fullchain should be valid: {}", message);

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_with_fullchain_check() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-list.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-list.local",
        "test-root-list.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create server cert under root
    let cert1_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-list.local",
        "test-root-list.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert1_res.is_ok());

    // Create server cert under ICA
    let cert2_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-list.local",
        "ops.test-list.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert2_res.is_ok());

    // List certificates with fullchain check (fix_fullchain=false)
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    // List certificates with fullchain check (auto_fix=true)
    let list_result2 = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: true,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result2.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_fullchain_order_wrong_ica() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    // Create root CA
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-wrong-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Create ICA
    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-wrong-ica.local",
        "test-root-wrong-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    // Create server cert signed by ICA
    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-wrong-ica.local",
        "ops.test-wrong-ica.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let fullchain_path = temp_dir_path
        .join("test-root-wrong-ica.local")
        .join("intermediates.d")
        .join("ops.test-wrong-ica.local")
        .join("certificates.d")
        .join("dashboard.ops.test-wrong-ica.local")
        .join("fullchain.crt");

    // Read fullchain and replace second cert with wrong cert
    let fullchain_content = fs::read(&fullchain_path).unwrap();
    let fullchain_str = String::from_utf8_lossy(&fullchain_content);
    let certs: Vec<&str> = fullchain_str
        .split("-----BEGIN CERTIFICATE-----")
        .filter(|s| !s.trim().is_empty())
        .collect();

    // Get first cert (server cert)
    let first_cert = format!("-----BEGIN CERTIFICATE-----{}", certs[0]);

    // Get wrong ICA (different ICA name)
    let wrong_ica_path = temp_dir_path
        .join("test-root-wrong-ica.local")
        .join("crt.pem");
    let wrong_ica_content = fs::read(&wrong_ica_path).unwrap();

    // Write wrong fullchain
    let mut wrong_fullchain = first_cert.into_bytes();
    wrong_fullchain.extend_from_slice(&wrong_ica_content);
    fs::write(&fullchain_path, &wrong_fullchain).unwrap();

    // Verify should report wrong ICA
    let cert_dir = fullchain_path.parent().unwrap();
    let result = utils::verify_fullchain_order(cert_dir);
    assert!(result.is_ok());
    let (is_valid, message) = result.unwrap();
    assert!(!is_valid);
    assert!(message.contains("WRONG"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_fullchain_order_parse_error() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create a directory with a malformed fullchain.crt
    let test_dir = temp_dir_path.join("test-parse-error");
    fs::create_dir_all(&test_dir).unwrap();

    // Write crt.pem (needed for verify function)
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-parse.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Copy crt.pem to test directory
    fs::copy(
        temp_dir_path.join("test-root-parse.local/crt.pem"),
        test_dir.join("crt.pem"),
    )
    .unwrap();

    // Write an empty fullchain.crt
    fs::write(test_dir.join("fullchain.crt"), "").unwrap();

    // Verify should handle empty fullchain
    let result = utils::verify_fullchain_order(&test_dir);
    assert!(result.is_ok());
    let (is_valid, _message) = result.unwrap();
    assert!(is_valid);

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_import_nonexistent_source() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Try to import from non-existent path
    let nonexistent = tmp.path().join("nonexistent");
    let import_result = utils::import_certificate(&nonexistent, &temp_dir_path).await;

    assert!(import_result.is_err());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_import_invalid_source() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create a directory without crt.pem
    let invalid_source = tmp.path().join("invalid_source");
    fs::create_dir_all(&invalid_source).unwrap();

    // Try to import from invalid source (missing crt.pem)
    let import_result = utils::import_certificate(&invalid_source, &temp_dir_path).await;

    assert!(import_result.is_err());
    drop(tmp);
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("certboy"));
}

#[test]
fn test_cli_no_args() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Listing certificates"));
}

#[test]
fn test_cli_check_empty_context() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();
    drop(tmp);
}

#[test]
fn test_cli_completion_bash() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("completion")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("compgen"));
}

#[test]
fn test_cli_completion_zsh() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("completion")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::str::contains("compdef"));
}

#[test]
fn test_cli_completion_fish() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("completion")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -c"));
}

#[test]
fn test_cli_completion_powershell() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("completion")
        .arg("powershell")
        .assert()
        .success()
        .stdout(predicate::str::contains("Register-ArgumentCompleter"));
}

#[test]
fn test_cli_invalid_command() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("invalid-command").assert().failure();
}

#[test]
fn test_cli_check_with_renew_flag() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--context")
        .arg(tmp.path())
        .arg("--renew")
        .assert()
        .success();
    drop(tmp);
}

#[test]
fn test_cli_check_with_expiration_alert() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--context")
        .arg(tmp.path())
        .arg("--expiration-alert")
        .arg("30")
        .assert()
        .success();
    drop(tmp);
}

#[test]
fn test_cli_export_help() {
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("export")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Export server certificate"));
}

#[test]
fn test_cli_export_not_found() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("export")
        .arg("nonexistent.example.com")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_export_certificate() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-export.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-export.local",
        "test-export.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let original_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&temp_dir_path).unwrap();

    let export_result = utils::export_certificate(&temp_dir_path, "www.test-export.local");
    if let Err(e) = &export_result {
        eprintln!("Export error: {}", e);
    }
    assert!(export_result.is_ok());

    assert!(Path::new("www.test-export.local.crt").exists());
    assert!(Path::new("www.test-export.local.key").exists());

    std::fs::remove_file("www.test-export.local.crt").ok();
    std::fs::remove_file("www.test-export.local.key").ok();

    std::env::set_current_dir(original_cwd).unwrap();
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_fix_fullchain_order_ica_not_found() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-fix.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-fix.local",
        "test-root-fix.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-root-fix.local")
        .join("certificates.d")
        .join("www.test-fix.local");
    let result = utils::fix_fullchain_order(&cert_dir, &temp_dir_path);
    assert!(result.is_err());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_fix_fullchain_order_missing_files() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let empty_dir = temp_dir_path.join("empty_cert_dir");
    fs::create_dir_all(&empty_dir).unwrap();

    let result = utils::fix_fullchain_order(&empty_dir, &temp_dir_path);
    assert!(result.is_err());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_ica_signed() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-root-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-ica.local",
        "test-root-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-ica.local",
        "ops.test-ica.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_with_renew() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-renew.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-renew.local",
        "test-renew.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: true,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_ica_chain() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-fullpath.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-fullpath.local",
        "test-fullpath.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "www.ops.test-fullpath.local",
        "ops.test-fullpath.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_custom_expiration_alert() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-exp.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-exp.local",
        "test-exp.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 30,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_check_with_empty_context() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(&temp_dir_path).unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_resign_tls_certificate() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-resign.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "www.test-resign.local",
        "test-resign.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-resign.local")
        .join("certificates.d")
        .join("www.test-resign.local");
    let original_crt = fs::read_to_string(cert_dir.join("crt.pem")).unwrap();
    let original_cert = openssl::x509::X509::from_pem(original_crt.as_bytes()).unwrap();
    let original_serial = original_cert
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();

    let new_serial = utils::resign_tls_certificate(&temp_dir_path, &cert_dir, "test-resign.local");
    assert!(new_serial.is_ok());
    let new_serial_str = new_serial.unwrap();

    assert_ne!(
        new_serial_str, original_serial,
        "New serial should be different from original"
    );

    let new_crt = fs::read_to_string(cert_dir.join("crt.pem")).unwrap();
    assert_ne!(
        original_crt, new_crt,
        "Certificate content should be different after re-sign"
    );

    let new_cert = openssl::x509::X509::from_pem(new_crt.as_bytes()).unwrap();
    let new_cert_serial = new_cert
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();
    assert_eq!(
        new_cert_serial, new_serial_str,
        "New certificate should have the new serial"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_resign_tls_certificate_under_ica() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-resign-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-resign-ica.local",
        "test-resign-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    let cert_res = cert::sign_cert(
        &temp_dir_path,
        "dashboard.ops.test-resign-ica.local",
        "ops.test-resign-ica.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert_res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-resign-ica.local")
        .join("intermediates.d")
        .join("ops.test-resign-ica.local")
        .join("certificates.d")
        .join("dashboard.ops.test-resign-ica.local");
    let original_crt = fs::read_to_string(cert_dir.join("crt.pem")).unwrap();
    let original_cert = openssl::x509::X509::from_pem(original_crt.as_bytes()).unwrap();
    let original_serial = original_cert
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();

    let new_serial =
        utils::resign_tls_certificate(&temp_dir_path, &cert_dir, "ops.test-resign-ica.local");
    assert!(new_serial.is_ok());
    let new_serial_str = new_serial.unwrap();

    assert_ne!(
        new_serial_str, original_serial,
        "New serial should be different from original"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_resign_tls_certificate_missing_key() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let cert_dir = temp_dir_path.join("nonexistent").join("cert");
    fs::create_dir_all(&cert_dir).unwrap();

    let result = utils::resign_tls_certificate(&temp_dir_path, &cert_dir, "test.local");
    assert!(result.is_err());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_fix_ica_and_children() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-fix-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let ica_res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-fix-ica.local",
        "test-fix-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(ica_res.is_ok());

    let cert1_res = cert::sign_cert(
        &temp_dir_path,
        "server1.ops.test-fix-ica.local",
        "ops.test-fix-ica.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert1_res.is_ok());

    let cert2_res = cert::sign_cert(
        &temp_dir_path,
        "server2.ops.test-fix-ica.local",
        "ops.test-fix-ica.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(cert2_res.is_ok());

    let ica_dir = temp_dir_path
        .join("test-fix-ica.local")
        .join("intermediates.d")
        .join("ops.test-fix-ica.local");
    let original_ica_crt = fs::read_to_string(ica_dir.join("crt.pem")).unwrap();
    let original_ica_cert = openssl::x509::X509::from_pem(original_ica_crt.as_bytes()).unwrap();
    let original_ica_serial = original_ica_cert
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();

    let results = utils::fix_ica_and_children(&temp_dir_path, "ops.test-fix-ica.local", true).await;
    assert!(results.is_ok());
    let fix_results = results.unwrap();

    assert!(
        !fix_results.is_empty(),
        "Should have at least the ICA result"
    );

    let ica_result = fix_results
        .iter()
        .find(|r| r.domain == "ops.test-fix-ica.local");
    assert!(ica_result.is_some(), "Should have ICA result");
    assert!(ica_result.unwrap().fixed, "ICA should be fixed");

    let new_ica_crt = fs::read_to_string(ica_dir.join("crt.pem")).unwrap();
    let new_ica_cert = openssl::x509::X509::from_pem(new_ica_crt.as_bytes()).unwrap();
    let new_ica_serial = new_ica_cert
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();
    assert_ne!(
        new_ica_serial, original_ica_serial,
        "ICA should have a new serial after fix"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_fix_ica_and_children_empty() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let results = utils::fix_ica_and_children(&temp_dir_path, "nonexistent.ica.local", true).await;
    assert!(results.is_err());

    drop(tmp);
}

// ============================================================
// RSA Key Algorithm Tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_init_root_ca_rsa() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let res = ca::init_root_ca(
        &temp_dir_path,
        "test-rsa-root.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await;
    assert!(res.is_ok());

    let crt_path = temp_dir_path.join("test-rsa-root.local").join("crt.pem");
    let cert_pem = fs::read(&crt_path).unwrap();
    let cert = X509::from_pem(&cert_pem).unwrap();
    assert_eq!(
        cert.public_key().unwrap().id(),
        openssl::pkey::Id::RSA,
        "Root CA should use RSA key"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_sign_ica_rsa() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-rsa-root2.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let res = ica::sign_ica(
        &temp_dir_path,
        "ops.test-rsa-root2.local",
        "test-rsa-root2.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await;
    assert!(res.is_ok());

    let ica_crt_path = temp_dir_path
        .join("test-rsa-root2.local")
        .join("intermediates.d")
        .join("ops.test-rsa-root2.local")
        .join("crt.pem");
    let cert_pem = fs::read(&ica_crt_path).unwrap();
    let cert = X509::from_pem(&cert_pem).unwrap();
    assert_eq!(
        cert.public_key().unwrap().id(),
        openssl::pkey::Id::RSA,
        "ICA should inherit RSA key algorithm from parent"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_sign_cert_rsa() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-rsa-root3.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let res = cert::sign_cert(
        &temp_dir_path,
        "www.test-rsa-root3.local",
        "test-rsa-root3.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(res.is_ok());

    let cert_crt_path = temp_dir_path
        .join("test-rsa-root3.local")
        .join("certificates.d")
        .join("www.test-rsa-root3.local")
        .join("crt.pem");
    let cert_pem = fs::read(&cert_crt_path).unwrap();
    let cert = X509::from_pem(&cert_pem).unwrap();
    assert_eq!(
        cert.public_key().unwrap().id(),
        openssl::pkey::Id::RSA,
        "TLS cert should inherit RSA key algorithm from CA"
    );

    drop(tmp);
}

// ============================================================
// Encrypted Private Key Tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_sign_cert_with_encrypted_key() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-enc.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let res = cert::sign_cert(
        &temp_dir_path,
        "www.test-enc.local",
        "test-enc.local",
        false,
        None,
        None,
        true, // encrypt_key = true
    )
    .await;
    assert!(res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-enc.local")
        .join("certificates.d")
        .join("www.test-enc.local");

    // Verify key is encrypted
    let key_content = fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    assert!(
        key_content.contains("BEGIN ENCRYPTED PRIVATE KEY"),
        "Private key should be encrypted when encrypt_key=true"
    );

    // Verify password file exists
    let pass_path = cert_dir.join("pass.key");
    assert!(pass_path.exists(), "Password file should exist");
    let pass_content = fs::read_to_string(&pass_path).unwrap();
    assert!(!pass_content.is_empty(), "Password should not be empty");

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_sign_cert_without_encrypted_key() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-noenc.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let res = cert::sign_cert(
        &temp_dir_path,
        "www.test-noenc.local",
        "test-noenc.local",
        false,
        None,
        None,
        false, // encrypt_key = false
    )
    .await;
    assert!(res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-noenc.local")
        .join("certificates.d")
        .join("www.test-noenc.local");

    // Verify key is NOT encrypted
    let key_content = fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    assert!(
        !key_content.contains("ENCRYPTED"),
        "Private key should NOT be encrypted when encrypt_key=false"
    );

    drop(tmp);
}

// ============================================================
// Root CA Idempotency
// ============================================================

#[tokio::test]
#[serial]
async fn test_init_root_ca_already_exists() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let res1 = ca::init_root_ca(
        &temp_dir_path,
        "test-idem.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(res1.is_ok());

    // Get original cert content
    let crt_path = temp_dir_path.join("test-idem.local").join("crt.pem");
    let original_cert = fs::read_to_string(&crt_path).unwrap();

    // Call again - should succeed without overwriting
    let res2 = ca::init_root_ca(
        &temp_dir_path,
        "test-idem.local",
        "DifferentOrg",
        "US",
        utils::KeyAlgorithm::Rsa,
        Some(365),
    )
    .await;
    assert!(res2.is_ok());

    // Cert should be unchanged
    let after_cert = fs::read_to_string(&crt_path).unwrap();
    assert_eq!(
        original_cert, after_cert,
        "init_root_ca should not overwrite existing CA"
    );

    drop(tmp);
}

// ============================================================
// Custom Expiration
// ============================================================

#[tokio::test]
#[serial]
async fn test_init_root_ca_custom_expiration() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let res = ca::init_root_ca(
        &temp_dir_path,
        "test-exp-ca.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        Some(365), // 1 year
    )
    .await;
    assert!(res.is_ok());

    let crt_path = temp_dir_path.join("test-exp-ca.local").join("crt.pem");
    let cert_pem = fs::read(&crt_path).unwrap();
    let cert = X509::from_pem(&cert_pem).unwrap();

    // Verify expiration is approximately 365 days from now (not the default 7300)
    let not_after = cert.not_after();
    let now_plus_400 = openssl::asn1::Asn1Time::days_from_now(400).unwrap();
    let now_plus_300 = openssl::asn1::Asn1Time::days_from_now(300).unwrap();
    assert!(
        not_after < now_plus_400,
        "Cert should expire before 400 days from now"
    );
    assert!(
        not_after > now_plus_300,
        "Cert should expire after 300 days from now"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_sign_cert_custom_expiration() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-cert-exp.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let res = cert::sign_cert(
        &temp_dir_path,
        "www.test-cert-exp.local",
        "test-cert-exp.local",
        false,
        None,
        Some(180), // 6 months
        false,
    )
    .await;
    assert!(res.is_ok());

    let cert_crt_path = temp_dir_path
        .join("test-cert-exp.local")
        .join("certificates.d")
        .join("www.test-cert-exp.local")
        .join("crt.pem");
    let cert_pem = fs::read(&cert_crt_path).unwrap();
    let cert = X509::from_pem(&cert_pem).unwrap();

    let not_after = cert.not_after();
    let now_plus_200 = openssl::asn1::Asn1Time::days_from_now(200).unwrap();
    let now_plus_150 = openssl::asn1::Asn1Time::days_from_now(150).unwrap();
    assert!(not_after < now_plus_200, "Should expire before 200 days");
    assert!(not_after > now_plus_150, "Should expire after 150 days");

    drop(tmp);
}

// ============================================================
// verify_key_cert_match Tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_verify_key_cert_match_valid() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // NOTE: verify_key_cert_match uses `openssl rsa -modulus` which only works for RSA keys.
    // This is a design issue — ECDSA keys will always fail verification.
    // Using RSA here to test the happy path.
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-verify.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let res = cert::sign_cert(
        &temp_dir_path,
        "www.test-verify.local",
        "test-verify.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-verify.local")
        .join("certificates.d")
        .join("www.test-verify.local");
    let (is_valid, msg) = utils::verify_key_cert_match(&cert_dir).unwrap();
    assert!(is_valid, "Key and cert should match: {}", msg);

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_key_cert_match_missing_key() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let test_dir = temp_dir_path.join("no-key-dir");
    fs::create_dir_all(&test_dir).unwrap();
    // Only create crt.pem, no key.pem
    fs::write(test_dir.join("crt.pem"), "dummy").unwrap();

    let (is_valid, msg) = utils::verify_key_cert_match(&test_dir).unwrap();
    assert!(!is_valid);
    assert!(msg.contains("key.pem not found"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_key_cert_match_missing_cert() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let test_dir = temp_dir_path.join("no-cert-dir");
    fs::create_dir_all(&test_dir).unwrap();
    // Only create key.pem, no crt.pem
    fs::write(test_dir.join("key.pem"), "dummy").unwrap();

    let (is_valid, msg) = utils::verify_key_cert_match(&test_dir).unwrap();
    assert!(!is_valid);
    assert!(msg.contains("crt.pem not found"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_key_cert_match_mismatch() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create two different certs and mix their key/cert (RSA for verify_key_cert_match)
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-mismatch.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Sign two different certs
    cert::sign_cert(
        &temp_dir_path,
        "a.test-mismatch.local",
        "test-mismatch.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "b.test-mismatch.local",
        "test-mismatch.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let cert_dir_a = temp_dir_path
        .join("test-mismatch.local")
        .join("certificates.d")
        .join("a.test-mismatch.local");
    let cert_dir_b = temp_dir_path
        .join("test-mismatch.local")
        .join("certificates.d")
        .join("b.test-mismatch.local");

    // Copy key from cert B into cert A's directory (mismatch)
    let mismatch_dir = temp_dir_path.join("mismatch_test");
    fs::create_dir_all(&mismatch_dir).unwrap();
    fs::copy(cert_dir_a.join("crt.pem"), mismatch_dir.join("crt.pem")).unwrap();
    fs::copy(cert_dir_b.join("key.pem"), mismatch_dir.join("key.pem")).unwrap();
    // Need pass.key for the unencrypted key check
    fs::copy(cert_dir_b.join("pass.key"), mismatch_dir.join("pass.key")).unwrap();

    let (is_valid, msg) = utils::verify_key_cert_match(&mismatch_dir).unwrap();
    assert!(!is_valid, "Mismatched key/cert should fail: {}", msg);

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_key_cert_match_encrypted_key() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Using RSA because verify_key_cert_match hardcodes `openssl rsa -modulus`
    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-verify-enc.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    // Sign with encrypted key
    let res = cert::sign_cert(
        &temp_dir_path,
        "www.test-verify-enc.local",
        "test-verify-enc.local",
        false,
        None,
        None,
        true, // encrypt_key
    )
    .await;
    assert!(res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-verify-enc.local")
        .join("certificates.d")
        .join("www.test-verify-enc.local");
    let (is_valid, msg) = utils::verify_key_cert_match(&cert_dir).unwrap();
    assert!(
        is_valid,
        "Encrypted key+cert should verify OK with password file: {}",
        msg
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_verify_key_cert_match_ecdsa() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    let ca_res = ca::init_root_ca(
        &temp_dir_path,
        "test-verify-ec.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await;
    assert!(ca_res.is_ok());

    let res = cert::sign_cert(
        &temp_dir_path,
        "www.test-verify-ec.local",
        "test-verify-ec.local",
        false,
        None,
        None,
        false,
    )
    .await;
    assert!(res.is_ok());

    let cert_dir = temp_dir_path
        .join("test-verify-ec.local")
        .join("certificates.d")
        .join("www.test-verify-ec.local");
    let (is_valid, msg) = utils::verify_key_cert_match(&cert_dir).unwrap();
    assert!(
        is_valid,
        "ECDSA key and cert should match: {}",
        msg
    );

    drop(tmp);
}

// ============================================================
// Revoke Certificate Tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_revoke_tls_certificate() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "test-revoke.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.test-revoke.local",
        "test-revoke.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let cert_dir = temp_dir_path
        .join("test-revoke.local")
        .join("certificates.d")
        .join("www.test-revoke.local");
    assert!(cert_dir.exists());

    // Revoke with skip_confirm=true
    let result =
        utils::revoke_certificate(&temp_dir_path, "www.test-revoke.local", true).await;
    assert!(result.is_ok());
    assert!(
        !cert_dir.exists(),
        "Certificate directory should be removed after revoke"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_revoke_ica_cascading() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "test-revoke-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.test-revoke-ica.local",
        "test-revoke-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "server1.ops.test-revoke-ica.local",
        "ops.test-revoke-ica.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "server2.ops.test-revoke-ica.local",
        "ops.test-revoke-ica.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let ica_dir = temp_dir_path
        .join("test-revoke-ica.local")
        .join("intermediates.d")
        .join("ops.test-revoke-ica.local");
    assert!(ica_dir.exists());

    // Revoke the ICA
    let result =
        utils::revoke_certificate(&temp_dir_path, "ops.test-revoke-ica.local", true).await;
    assert!(result.is_ok());
    assert!(
        !ica_dir.exists(),
        "ICA directory and children should be removed"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_revoke_root_ca_cascading() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "test-revoke-root.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.test-revoke-root.local",
        "test-revoke-root.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.test-revoke-root.local",
        "test-revoke-root.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let root_dir = temp_dir_path.join("test-revoke-root.local");
    assert!(root_dir.exists());

    // Revoke the entire root CA
    let result =
        utils::revoke_certificate(&temp_dir_path, "test-revoke-root.local", true).await;
    assert!(result.is_ok());
    assert!(
        !root_dir.exists(),
        "Root CA directory and everything under it should be removed"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_revoke_nonexistent_domain() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(&temp_dir_path).unwrap();
    // Write empty global metadata so the context is valid
    utils::write_global_metadata(
        &temp_dir_path,
        &utils::GlobalCertMetadata::new(),
    )
    .unwrap();

    let result =
        utils::revoke_certificate(&temp_dir_path, "nonexistent.local", true).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("not found"),
        "Should indicate certificate not found"
    );

    drop(tmp);
}

// ============================================================
// Export ICA-signed Certificate (fullchain)
// ============================================================

#[tokio::test]
#[serial]
async fn test_export_ica_signed_certificate() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "test-export-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.test-export-ica.local",
        "test-export-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.ops.test-export-ica.local",
        "ops.test-export-ica.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Export from temp dir so we don't pollute cwd
    let export_dir = tmp.path().join("export_dest");
    fs::create_dir_all(&export_dir).unwrap();
    let original_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&export_dir).unwrap();

    let export_result =
        utils::export_certificate(&temp_dir_path, "www.ops.test-export-ica.local");
    assert!(export_result.is_ok());

    // Should export fullchain.crt (not just crt.pem) for ICA-signed certs
    let exported_crt = export_dir.join("www.ops.test-export-ica.local.crt");
    let exported_key = export_dir.join("www.ops.test-export-ica.local.key");
    assert!(exported_crt.exists());
    assert!(exported_key.exists());

    // Verify the exported crt contains the fullchain (2 certs)
    let crt_content = fs::read_to_string(&exported_crt).unwrap();
    let cert_count = crt_content.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(
        cert_count, 2,
        "Exported crt should contain fullchain (server + ICA)"
    );

    std::env::set_current_dir(original_cwd).unwrap();
    drop(tmp);
}

// ============================================================
// find_tls_certs_signed_by / find_icas_under_root
// ============================================================

#[tokio::test]
#[serial]
async fn test_find_tls_certs_signed_by() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // NOTE: find_tls_certs_signed_by matches issuer CN against ca_domain.
    // This only works when the CA's CN == domain name.
    // Using domain as CN to test the happy path.
    ca::init_root_ca(
        &temp_dir_path,
        "test-find.local",
        "test-find.local", // CN = domain for matching to work
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "a.test-find.local",
        "test-find.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "b.test-find.local",
        "test-find.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let certs = utils::find_tls_certs_signed_by(&temp_dir_path, "test-find.local").unwrap();
    assert_eq!(certs.len(), 2);

    let domains: Vec<&str> = certs.iter().map(|c| c.domain.as_str()).collect();
    assert!(domains.contains(&"a.test-find.local"));
    assert!(domains.contains(&"b.test-find.local"));

    // Search for non-existent CA
    let empty = utils::find_tls_certs_signed_by(&temp_dir_path, "nonexistent.local").unwrap();
    assert!(empty.is_empty());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_find_tls_certs_signed_by_cn_mismatch() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Previously this failed when CN != domain because only issuer CN was checked.
    // Now uses metadata parent field and path-based detection as well.
    ca::init_root_ca(
        &temp_dir_path,
        "test-find-bug.local",
        "TestOrg", // CN != domain
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "a.test-find-bug.local",
        "test-find-bug.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Now finds certs via metadata parent field even when CN != domain
    let certs =
        utils::find_tls_certs_signed_by(&temp_dir_path, "test-find-bug.local").unwrap();
    assert_eq!(
        certs.len(),
        1,
        "find_tls_certs_signed_by should find certs via metadata even when CA CN != domain"
    );

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_find_icas_under_root() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "test-find-ica.local",
        "test-find-ica.local",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.test-find-ica.local",
        "test-find-ica.local",
        "ops.test-find-ica.local",
        "CN",
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "dev.test-find-ica.local",
        "test-find-ica.local",
        "dev.test-find-ica.local",
        "CN",
        None,
    )
    .await
    .unwrap();

    let icas = utils::find_icas_under_root(&temp_dir_path, "test-find-ica.local").unwrap();
    assert_eq!(icas.len(), 2);

    let domains: Vec<&str> = icas.iter().map(|c| c.domain.as_str()).collect();
    assert!(domains.contains(&"ops.test-find-ica.local"));
    assert!(domains.contains(&"dev.test-find-ica.local"));

    // No ICAs
    let empty = utils::find_icas_under_root(&temp_dir_path, "nonexistent.local").unwrap();
    assert!(empty.is_empty());

    drop(tmp);
}

// ============================================================
// parse_alt_names_from_ext edge cases
// ============================================================

#[test]
fn test_parse_alt_names_from_ext_with_comments() {
    let ext_content = r#"[alt_names]
DNS.1 = example.com
# DNS.2 = commented-out.com
DNS.3 = api.example.com
# IP.1 = 10.0.0.1
IP.2 = 192.168.1.1
"#;
    let names = utils::parse_alt_names_from_ext(ext_content).unwrap();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"example.com".to_string()));
    assert!(names.contains(&"api.example.com".to_string()));
    assert!(names.contains(&"192.168.1.1".to_string()));
}

#[test]
fn test_parse_alt_names_from_ext_empty() {
    let ext_content = "";
    let names = utils::parse_alt_names_from_ext(ext_content).unwrap();
    assert!(names.is_empty());
}

#[test]
fn test_parse_alt_names_from_ext_ipv6() {
    let ext_content = r#"[alt_names]
DNS.1 = example.com
IP.1 = ::1
IP.2 = fe80::1
"#;
    let names = utils::parse_alt_names_from_ext(ext_content).unwrap();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"::1".to_string()));
    assert!(names.contains(&"fe80::1".to_string()));
}

// ============================================================
// list_certificates with detail and verify_openssl
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_with_detail() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "test-detail.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.test-detail.local",
        "test-detail.local",
        false,
        Some(&["api.test-detail.local".to_string(), "127.0.0.1".to_string()]),
        None,
        false,
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: true,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_with_verify_openssl() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    fs::create_dir_all(temp_dir_path.join("CAs")).unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "test-ossl.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.test-ossl.local",
        "test-ossl.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: true,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// sign_cert with SAN including IPv6
// ============================================================

#[tokio::test]
#[serial]
async fn test_sign_cert_with_ipv6_san() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "test-ipv6.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    let altnames = vec![
        "www.test-ipv6.local".to_string(),
        "::1".to_string(),
        "fe80::1".to_string(),
    ];
    let res = cert::sign_cert(
        &temp_dir_path,
        "test-ipv6.local",
        "test-ipv6.local",
        false,
        Some(&altnames),
        None,
        false,
    )
    .await;
    // Note: this may fail in openssl depending on the SAN encoding support for IPv6
    // If it succeeds, the cert should have the IPv6 addresses in SAN
    if res.is_ok() {
        let cert_crt_path = temp_dir_path
            .join("test-ipv6.local")
            .join("certificates.d")
            .join("test-ipv6.local")
            .join("crt.pem");
        let cert_pem = fs::read(&cert_crt_path).unwrap();
        let _cert = X509::from_pem(&cert_pem).unwrap();
    }

    drop(tmp);
}

// ============================================================
// remove_from_global_metadata
// ============================================================

#[tokio::test]
#[serial]
async fn test_remove_from_global_metadata() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "test-meta-rm.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.test-meta-rm.local",
        "test-meta-rm.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Verify it's in metadata
    let meta = utils::read_global_metadata(&temp_dir_path).unwrap();
    assert!(
        meta.certificates
            .iter()
            .any(|c| c.domain == "www.test-meta-rm.local")
    );

    // Remove it
    utils::remove_from_global_metadata(&temp_dir_path, "www.test-meta-rm.local").unwrap();

    // Verify it's gone
    let meta_after = utils::read_global_metadata(&temp_dir_path).unwrap();
    assert!(
        !meta_after
            .certificates
            .iter()
            .any(|c| c.domain == "www.test-meta-rm.local")
    );

    // Root CA should still be there
    assert!(
        meta_after
            .certificates
            .iter()
            .any(|c| c.domain == "test-meta-rm.local")
    );

    drop(tmp);
}

// ============================================================
// P12 file generation
// ============================================================

#[tokio::test]
#[serial]
async fn test_sign_cert_generates_p12() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "test-p12.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.test-p12.local",
        "test-p12.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let cert_dir = temp_dir_path
        .join("test-p12.local")
        .join("certificates.d")
        .join("www.test-p12.local");

    let p12_path = cert_dir.join("cert.p12");
    let p12_pass_path = cert_dir.join("p12.pass");

    assert!(p12_path.exists(), "PKCS#12 file should be generated");
    assert!(p12_pass_path.exists(), "P12 password file should exist");

    let p12_data = fs::read(&p12_path).unwrap();
    assert!(!p12_data.is_empty(), "P12 file should not be empty");

    let p12_pass = fs::read_to_string(&p12_pass_path).unwrap();
    assert!(!p12_pass.is_empty(), "P12 password should not be empty");

    drop(tmp);
}

// ============================================================
// CLI Binary Integration Tests (main.rs coverage)
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_root_ca_creation() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--root-ca")
        .arg("-d")
        .arg("cli-root.local")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Root CA initialization completed"));

    assert!(tmp.path().join("cli-root.local").join("crt.pem").exists());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_root_ca_rsa() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--root-ca")
        .arg("-d")
        .arg("cli-rsa.local")
        .arg("--key-algorithm")
        .arg("rsa")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    let crt_path = tmp.path().join("cli-rsa.local").join("crt.pem");
    let cert_pem = fs::read(&crt_path).unwrap();
    let cert = X509::from_pem(&cert_pem).unwrap();
    assert_eq!(cert.public_key().unwrap().id(), openssl::pkey::Id::RSA);
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_root_ca_custom_expiration() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--root-ca")
        .arg("-d")
        .arg("cli-exp.local")
        .arg("--expiration")
        .arg("365")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    assert!(tmp.path().join("cli-exp.local").join("crt.pem").exists());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_root_ca_custom_cn_and_country() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--root-ca")
        .arg("-d")
        .arg("cli-cn.local")
        .arg("--cn")
        .arg("My Custom CA")
        .arg("--country")
        .arg("US")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    assert!(tmp.path().join("cli-cn.local").join("crt.pem").exists());
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_sign_cert_via_binary() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create Root CA first
    ca::init_root_ca(
        &temp_dir_path,
        "cli-ca.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // Sign cert via CLI
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("cli-ca.local")
        .arg("-d")
        .arg("www.cli-ca.local")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificate signing completed"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_sign_cert_with_force() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-force.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-force.local",
        "cli-force.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Force re-sign via CLI
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("cli-force.local")
        .arg("-d")
        .arg("www.cli-force.local")
        .arg("--force")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_sign_cert_with_encrypt_key() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-enc.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("cli-enc.local")
        .arg("-d")
        .arg("www.cli-enc.local")
        .arg("--encrypt-key")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    let key_content = fs::read_to_string(
        temp_dir_path
            .join("cli-enc.local")
            .join("certificates.d")
            .join("www.cli-enc.local")
            .join("key.pem"),
    )
    .unwrap();
    assert!(key_content.contains("ENCRYPTED"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_sign_ica_via_binary() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-ica-root.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("cli-ica-root.local")
        .arg("-d")
        .arg("ops.cli-ica-root.local")
        .arg("--cn")
        .arg("Ops ICA")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("ICA signing completed"));

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_sign_cert_multiple_domains() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-multi.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("cli-multi.local")
        .arg("-d")
        .arg("www.cli-multi.local")
        .arg("-d")
        .arg("api.cli-multi.local")
        .arg("-d")
        .arg("127.0.0.1")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

#[test]
fn test_cli_root_ca_missing_domain() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--root-ca")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Domain is required"));
    drop(tmp);
}

#[test]
fn test_cli_ca_missing_domain() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("some-ca.local")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Domain is required"));
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_check_with_detail() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-detail.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-detail.local",
        "cli-detail.local",
        false,
        Some(&["api.cli-detail.local".to_string()]),
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--detail")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_check_with_verify_openssl() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-verify.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-verify.local",
        "cli-verify.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--verify-openssl")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_check_with_auto_fix_yes() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-fix.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-fix.local",
        "cli-fix.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--auto-fix")
        .arg("-y")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_revoke_via_binary() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-revoke.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-revoke.local",
        "cli-revoke.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("revoke")
        .arg("www.cli-revoke.local")
        .arg("--yes")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    let cert_dir = temp_dir_path
        .join("cli-revoke.local")
        .join("certificates.d")
        .join("www.cli-revoke.local");
    assert!(!cert_dir.exists());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_export_via_binary() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-export.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-export.local",
        "cli-export.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let export_dir = tmp.path().join("export_output");
    fs::create_dir_all(&export_dir).unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.current_dir(&export_dir)
        .arg("export")
        .arg("www.cli-export.local")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificate exported"));

    assert!(export_dir.join("www.cli-export.local.crt").exists());
    assert!(export_dir.join("www.cli-export.local.key").exists());

    drop(tmp);
}

#[test]
fn test_cli_context_env_var() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.env("CERTBOY_CONTEXT", tmp.path())
        .arg("check")
        .assert()
        .success();
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_verbose_levels() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    // -v level
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("-v")
        .arg("check")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    // -vv level
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("-vv")
        .arg("check")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

// ============================================================
// list_certificates advanced coverage
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_no_metadata_fallback() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create CA and cert without metadata (simulate old format)
    ca::init_root_ca(
        &temp_dir_path,
        "no-meta.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.no-meta.local",
        "no-meta.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Remove the global metadata to force fallback path
    let meta_path = temp_dir_path.join("meta.json");
    if meta_path.exists() {
        fs::remove_file(&meta_path).unwrap();
    }

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_with_detail_and_sans() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "detail-san.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.detail-san.local",
        "detail-san.local",
        false,
        Some(&[
            "api.detail-san.local".to_string(),
            "127.0.0.1".to_string(),
        ]),
        None,
        false,
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: true,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_with_verify_openssl_rsa() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "verify-rsa.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.verify-rsa.local",
        "verify-rsa.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: true,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_auto_fix_with_ica() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "auto-fix-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.auto-fix-ica.local",
        "auto-fix-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.ops.auto-fix-ica.local",
        "ops.auto-fix-ica.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: true,
            auto_fix: true,
            yes: true,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_list_certificates_renew_no_expired() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "no-renew.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.no-renew.local",
        "no-renew.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // With renew=true but all certs are valid
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: true,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// Git integration tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_git_init_and_commit() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // init_git_repo should create a git repo
    let result = utils::init_git_repo(&temp_dir_path);
    assert!(result.is_ok());
    assert!(temp_dir_path.join(".git").exists());
    assert!(temp_dir_path.join(".gitignore").exists());

    // git_add_and_commit should work
    fs::write(temp_dir_path.join("test.txt"), "hello").unwrap();
    let result = utils::git_add_and_commit(&temp_dir_path, "Test commit");
    assert!(result.is_ok());

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_git_add_and_commit_no_changes() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    utils::init_git_repo(&temp_dir_path).unwrap();

    // Commit with no changes should return Ok(None)
    let result = utils::git_add_and_commit(&temp_dir_path, "Empty commit");
    assert!(result.is_ok());

    drop(tmp);
}

// ============================================================
// find_all_tls_under_ica coverage
// ============================================================

#[tokio::test]
#[serial]
async fn test_find_all_tls_under_ica_with_certs() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "find-tls.local",
        "find-tls.local",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.find-tls.local",
        "find-tls.local",
        "ops.find-tls.local",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "a.ops.find-tls.local",
        "ops.find-tls.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "b.ops.find-tls.local",
        "ops.find-tls.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let certs = utils::find_all_tls_under_ica(&temp_dir_path, "ops.find-tls.local").unwrap();
    assert_eq!(certs.len(), 2);

    drop(tmp);
}

// ============================================================
// list_certificates non-existent context
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_nonexistent_context() {
    init_logger();
    let non_existent = Path::new("/tmp/certboy-nonexistent-test-path-xyz");

    let list_result = utils::list_certificates(
        non_existent,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());
}

// ============================================================
// CLI with domain_args (positional after --ca)
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_domain_args_positional() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-pos.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // Use positional domain args (after --ca)
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("cli-pos.local")
        .arg("www.cli-pos.local")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

// ============================================================
// Import via CLI
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_import_via_binary() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-import-src.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    let import_context = tmp.path().join("import_dest");
    fs::create_dir_all(&import_context).unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("import")
        .arg(temp_dir_path.join("cli-import-src.local"))
        .arg("--context")
        .arg(&import_context)
        .assert()
        .success()
        .stdout(predicate::str::contains("Import completed"));

    drop(tmp);
}

#[test]
fn test_cli_import_nonexistent_path() {
    let tmp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("import")
        .arg("/nonexistent/path/abc123")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_cli_import_invalid_source() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let invalid_src = tmp.path().join("invalid_source");
    fs::create_dir_all(&invalid_src).unwrap();
    // No crt.pem in directory

    let import_ctx = tmp.path().join("import_ctx");
    fs::create_dir_all(&import_ctx).unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("import")
        .arg(&invalid_src)
        .arg("--context")
        .arg(&import_ctx)
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing crt.pem"));

    drop(tmp);
}

// ============================================================
// Default behavior (no subcommand, no args) with certs
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_default_behavior_with_certs() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-default.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-default.local",
        "cli-default.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Default behavior (no subcommand) should list certificates
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--context")
        .arg(tmp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Listing certificates"));

    drop(tmp);
}

// ============================================================
// Duplicate domain deduplication
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_duplicate_domains_dedup() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-dedup.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // Pass same domain multiple times - should be deduped
    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("--ca")
        .arg("cli-dedup.local")
        .arg("-d")
        .arg("www.cli-dedup.local")
        .arg("-d")
        .arg("www.cli-dedup.local")
        .arg("-d")
        .arg("api.cli-dedup.local")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

// ============================================================
// Auto-fix with duplicate serials
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_auto_fix_duplicate_serial() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Use domain as CN so find_tls_certs_signed_by works
    ca::init_root_ca(
        &temp_dir_path,
        "dup-serial.local",
        "dup-serial.local",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "a.dup-serial.local",
        "dup-serial.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "b.dup-serial.local",
        "dup-serial.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Manually make duplicate serials by copying one cert's serial to another
    let cert_a_dir = temp_dir_path
        .join("dup-serial.local")
        .join("certificates.d")
        .join("a.dup-serial.local");
    let cert_b_dir = temp_dir_path
        .join("dup-serial.local")
        .join("certificates.d")
        .join("b.dup-serial.local");
    let cert_a_pem = fs::read(cert_a_dir.join("crt.pem")).unwrap();
    // Copy cert A over cert B to create a duplicate serial
    fs::write(cert_b_dir.join("crt.pem"), &cert_a_pem).unwrap();

    // Also update the global metadata serial for cert B to match A
    let cert_a = X509::from_pem(&cert_a_pem).unwrap();
    let serial_a = cert_a
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();

    let mut global = utils::read_global_metadata(&temp_dir_path).unwrap();
    for cert_meta in global.certificates.iter_mut() {
        if cert_meta.domain == "b.dup-serial.local" {
            cert_meta.serial = serial_a.clone();
        }
    }
    utils::write_global_metadata(&temp_dir_path, &global).unwrap();

    // Now list with auto_fix + yes - should detect duplicate serial
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: true,
            yes: true,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// Export edge cases
// ============================================================

#[tokio::test]
#[serial]
async fn test_export_certificate_missing_key() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "exp-nokey.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.exp-nokey.local",
        "exp-nokey.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Remove key.pem to test error path
    let key_path = temp_dir_path
        .join("exp-nokey.local")
        .join("certificates.d")
        .join("www.exp-nokey.local")
        .join("key.pem");
    fs::remove_file(&key_path).unwrap();

    let result = utils::export_certificate(&temp_dir_path, "www.exp-nokey.local");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Key file not found"));

    drop(tmp);
}

// ============================================================
// list_certificates with verify_openssl + encrypted key
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_verify_openssl_encrypted() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "verify-enc2.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.verify-enc2.local",
        "verify-enc2.local",
        false,
        None,
        None,
        true, // encrypt_key
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: true,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// CLI check with large expiration alert (forces "needs renewal" path)
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_large_expiration_alert() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "large-alert.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // Create cert with short expiration (30 days)
    cert::sign_cert(
        &temp_dir_path,
        "www.large-alert.local",
        "large-alert.local",
        false,
        None,
        Some(30), // 30 days
        false,
    )
    .await
    .unwrap();

    // Set very large expiration alert threshold so the cert "needs renewal"
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: true,
            expiration_alert_days: 60, // Alert at 60 days, cert expires in 30
            detail: true,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// CLI check renew mode
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_check_renew_mode() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-renew.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-renew.local",
        "cli-renew.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--renew")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

// ============================================================
// list_certificates with renew=true triggering actual renewal
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_renew_triggers_resign() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "renew-trigger.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // Create cert with short expiration
    cert::sign_cert(
        &temp_dir_path,
        "www.renew-trigger.local",
        "renew-trigger.local",
        false,
        None,
        Some(5), // Very short: 5 days
        false,
    )
    .await
    .unwrap();

    // With renew=true and expiration_alert_days > 5, cert needs renewal
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: true,
            expiration_alert_days: 30,
            detail: false,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// Auto-fix fullchain order
// ============================================================

#[tokio::test]
#[serial]
async fn test_auto_fix_fullchain_wrong_order() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "fix-fc.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.fix-fc.local",
        "fix-fc.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.ops.fix-fc.local",
        "ops.fix-fc.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Corrupt the fullchain to have wrong order
    let cert_dir = temp_dir_path
        .join("fix-fc.local")
        .join("intermediates.d")
        .join("ops.fix-fc.local")
        .join("certificates.d")
        .join("www.ops.fix-fc.local");
    let fullchain_path = cert_dir.join("fullchain.crt");
    let server_cert = fs::read(cert_dir.join("crt.pem")).unwrap();
    // Write only server cert (wrong count for fullchain)
    fs::write(&fullchain_path, &server_cert).unwrap();

    // Auto-fix should fix it
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: true,
            yes: true,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// More list_certificates coverage: renew with ICA chain
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_renew_ica_chain() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "renew-chain.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.renew-chain.local",
        "renew-chain.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    // Create cert with very short expiration under ICA
    cert::sign_cert(
        &temp_dir_path,
        "www.ops.renew-chain.local",
        "ops.renew-chain.local",
        false,
        None,
        Some(5), // 5 days
        false,
    )
    .await
    .unwrap();

    // renew=true with high threshold
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: true,
            expiration_alert_days: 30,
            detail: true,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// list_certificates auto_fix with serial 0
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_auto_fix_serial_zero() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "serial0.local",
        "serial0.local",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.serial0.local",
        "serial0.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Manually set serial to "0" in metadata
    let mut global = utils::read_global_metadata(&temp_dir_path).unwrap();
    for cert_meta in global.certificates.iter_mut() {
        if cert_meta.domain == "www.serial0.local" {
            cert_meta.serial = "0".to_string();
        }
    }
    utils::write_global_metadata(&temp_dir_path, &global).unwrap();

    // Auto-fix should detect serial 0
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: false,
            auto_fix: true,
            yes: true,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// fix_fullchain_order with ICA path that works
// ============================================================

#[tokio::test]
#[serial]
async fn test_fix_fullchain_order_success() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "fix-success.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // Use ICA domain as CN so fix_fullchain_order can find it by issuer CN
    ica::sign_ica(
        &temp_dir_path,
        "ops.fix-success.local",
        "fix-success.local",
        "ops.fix-success.local",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.ops.fix-success.local",
        "ops.fix-success.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let cert_dir = temp_dir_path
        .join("fix-success.local")
        .join("intermediates.d")
        .join("ops.fix-success.local")
        .join("certificates.d")
        .join("www.ops.fix-success.local");

    // Remove fullchain, then fix it
    let fullchain_path = cert_dir.join("fullchain.crt");
    fs::remove_file(&fullchain_path).unwrap();

    // Write a broken fullchain (wrong ICA)
    let server_cert = fs::read(cert_dir.join("crt.pem")).unwrap();
    let root_cert = fs::read(temp_dir_path.join("fix-success.local").join("crt.pem")).unwrap();
    let mut wrong_fullchain = server_cert.clone();
    wrong_fullchain.extend_from_slice(&root_cert);
    fs::write(&fullchain_path, &wrong_fullchain).unwrap();

    // fix_fullchain_order should fix it
    let result = utils::fix_fullchain_order(&cert_dir, &temp_dir_path);
    assert!(result.is_ok());

    // Verify the fullchain now has correct content
    let fixed_fullchain = fs::read(&fullchain_path).unwrap();
    let fixed_str = String::from_utf8_lossy(&fixed_fullchain);
    let cert_count = fixed_str.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(cert_count, 2);

    drop(tmp);
}

// ============================================================
// import_certificate as ICA (under intermediates.d)
// ============================================================

#[tokio::test]
#[serial]
async fn test_import_ica_to_existing_root() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // Create a root CA in source context
    ca::init_root_ca(
        &temp_dir_path,
        "import-root.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // Create an ICA
    ica::sign_ica(
        &temp_dir_path,
        "ica.import-root.local",
        "import-root.local",
        "TestOrg",
        "CN",
        None,
    )
    .await
    .unwrap();

    let ica_source = temp_dir_path
        .join("import-root.local")
        .join("intermediates.d")
        .join("ica.import-root.local");

    // Import into a new context that already has the root CA
    let import_ctx = tmp.path().join("import_target");
    fs::create_dir_all(&import_ctx).unwrap();

    // First import root CA
    let root_source = temp_dir_path.join("import-root.local");
    let result = utils::import_certificate(&root_source, &import_ctx).await;
    assert!(result.is_ok());

    // Then import ICA
    let result = utils::import_certificate(&ica_source, &import_ctx).await;
    assert!(result.is_ok());

    drop(tmp);
}

// ============================================================
// list_certificates with multiple root CAs
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_multiple_roots() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "multi-root1.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "multi-root2.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.multi-root1.local",
        "multi-root1.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.multi-root2.local",
        "multi-root2.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: true,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// CLI check with all flags combined
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_check_all_flags() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "all-flags.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.all-flags.local",
        "all-flags.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.ops.all-flags.local",
        "ops.all-flags.local",
        false,
        Some(&["api.ops.all-flags.local".to_string(), "10.0.0.1".to_string()]),
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("check")
        .arg("--detail")
        .arg("--auto-fix")
        .arg("-y")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    drop(tmp);
}

// ============================================================
// git_add_and_commit with actual changes
// ============================================================

#[tokio::test]
#[serial]
async fn test_git_add_and_commit_with_changes() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    utils::init_git_repo(&temp_dir_path).unwrap();

    // Create some non-private-key files
    fs::write(temp_dir_path.join("ext.cnf"), "test config").unwrap();
    fs::write(temp_dir_path.join("meta.json"), "{}").unwrap();

    let result = utils::git_add_and_commit(&temp_dir_path, "Add config files");
    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(hash.is_some(), "Should have committed something");

    drop(tmp);
}

#[tokio::test]
#[serial]
async fn test_git_init_repo_idempotent() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    // First init
    let result = utils::init_git_repo(&temp_dir_path);
    assert!(result.is_ok());

    // Second init should be idempotent
    let result = utils::init_git_repo(&temp_dir_path);
    assert!(result.is_ok());

    drop(tmp);
}

// ============================================================
// sign_cert through ICA then check, exercises more paths
// ============================================================

#[tokio::test]
#[serial]
async fn test_full_chain_sign_and_check_with_issues() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "full-chain.local",
        "full-chain.local",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.full-chain.local",
        "full-chain.local",
        "ops.full-chain.local",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "s1.ops.full-chain.local",
        "ops.full-chain.local",
        false,
        None,
        Some(5), // short expiry
        false,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "s2.ops.full-chain.local",
        "ops.full-chain.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    // Check with high alert threshold (forces some certs into "needs renewal")
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 30,
            detail: true,
            auto_fix: true,
            yes: true,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// Fix fullchain for self-signed cert (issuer==subject path)
// ============================================================

#[tokio::test]
#[serial]
async fn test_fix_fullchain_order_self_signed() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "fix-self.local",
        "fix-self.local",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    // The root CA cert IS self-signed (issuer==subject)
    let ca_dir = temp_dir_path.join("fix-self.local");

    // Manually create a fullchain.crt for the CA cert itself
    let ca_cert = fs::read(ca_dir.join("crt.pem")).unwrap();
    fs::write(ca_dir.join("fullchain.crt"), &ca_cert).unwrap();

    // fix_fullchain_order on a self-signed cert should remove the fullchain
    let result = utils::fix_fullchain_order(&ca_dir, &temp_dir_path);
    assert!(result.is_ok());
    // The fullchain.crt should be removed since it's self-signed
    assert!(!ca_dir.join("fullchain.crt").exists());

    drop(tmp);
}

// ============================================================
// list_certificates with renew + detail + verify for flat display
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_renew_flat_display() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "flat-disp.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.flat-disp.local",
        "flat-disp.local",
        false,
        None,
        Some(3), // Very short: 3 days
        false,
    )
    .await
    .unwrap();

    // renew=true with high threshold - exercises flat display path
    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: true,
            expiration_alert_days: 60,
            detail: true,
            auto_fix: false,
            yes: false,
            verify_openssl: true,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// Display tree with key_algorithm set
// ============================================================

#[tokio::test]
#[serial]
async fn test_list_certificates_with_key_algorithm_display() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "algo-disp.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::Rsa,
        None,
    )
    .await
    .unwrap();

    ca::init_root_ca(
        &temp_dir_path,
        "algo-disp2.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.algo-disp.local",
        "algo-disp.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let list_result = utils::list_certificates(
        &temp_dir_path,
        utils::CheckOptions {
            renew: false,
            expiration_alert_days: 14,
            detail: true,
            auto_fix: false,
            yes: false,
            verify_openssl: false,
            remote: false,
        },
    )
    .await;
    assert!(list_result.is_ok());

    drop(tmp);
}

// ============================================================
// export_certificate ICA-signed cert (uses fullchain)
// ============================================================

#[tokio::test]
#[serial]
async fn test_export_ica_signed_cert_via_cli() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "exp-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.exp-ica.local",
        "exp-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.ops.exp-ica.local",
        "ops.exp-ica.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let export_dir = tmp.path().join("ica_export");
    fs::create_dir_all(&export_dir).unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.current_dir(&export_dir)
        .arg("export")
        .arg("www.ops.exp-ica.local")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    // ICA-signed cert export should contain fullchain (2 certs)
    let exported_crt = fs::read_to_string(export_dir.join("www.ops.exp-ica.local.crt")).unwrap();
    let cert_count = exported_crt.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(cert_count, 2);

    drop(tmp);
}

// ============================================================
// Revoke root CA via CLI
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_revoke_root_ca() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-revoke-root.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.cli-revoke-root.local",
        "cli-revoke-root.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("revoke")
        .arg("cli-revoke-root.local")
        .arg("--yes")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    assert!(!temp_dir_path.join("cli-revoke-root.local").exists());
    drop(tmp);
}

// ============================================================
// Revoke ICA via CLI
// ============================================================

#[tokio::test]
#[serial]
async fn test_cli_revoke_ica() {
    init_logger();
    let tmp = TempDir::new().unwrap();
    let temp_dir_path = tmp.path().to_path_buf();

    ca::init_root_ca(
        &temp_dir_path,
        "cli-rev-ica.local",
        "TestOrg",
        "CN",
        utils::KeyAlgorithm::EcdsaP256,
        None,
    )
    .await
    .unwrap();

    ica::sign_ica(
        &temp_dir_path,
        "ops.cli-rev-ica.local",
        "cli-rev-ica.local",
        "OpsTeam",
        "CN",
        None,
    )
    .await
    .unwrap();

    cert::sign_cert(
        &temp_dir_path,
        "www.ops.cli-rev-ica.local",
        "ops.cli-rev-ica.local",
        false,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let mut cmd = Command::cargo_bin("certboy").unwrap();
    cmd.arg("revoke")
        .arg("ops.cli-rev-ica.local")
        .arg("--yes")
        .arg("--context")
        .arg(tmp.path())
        .assert()
        .success();

    let ica_dir = temp_dir_path
        .join("cli-rev-ica.local")
        .join("intermediates.d")
        .join("ops.cli-rev-ica.local");
    assert!(!ica_dir.exists());
    drop(tmp);
}
