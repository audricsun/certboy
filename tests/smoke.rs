use assert_cmd::Command;
use certboy::{ca, cert, ica, utils};
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
    let list_result =
        utils::list_certificates(&temp_dir_path, false, 14, false, false, false, false).await;
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
    let list_result =
        utils::list_certificates(&temp_dir_path, false, 14, false, false, false, false).await;
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
    let result = utils::verify_fullchain_order(&fullchain_path.parent().unwrap());
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
    let list_result =
        utils::list_certificates(&temp_dir_path, false, 14, false, false, false, false).await;
    assert!(list_result.is_ok());

    // List certificates with fullchain check (auto_fix=true)
    let list_result2 =
        utils::list_certificates(&temp_dir_path, false, 14, true, false, false, false).await;
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

    let list_result =
        utils::list_certificates(&temp_dir_path, false, 14, false, false, false, false).await;
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

    let list_result =
        utils::list_certificates(&temp_dir_path, true, 14, false, false, false, false).await;
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

    let list_result =
        utils::list_certificates(&temp_dir_path, false, 14, false, false, false, false).await;
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

    let list_result =
        utils::list_certificates(&temp_dir_path, false, 30, false, false, false, false).await;
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

    let list_result =
        utils::list_certificates(&temp_dir_path, false, 14, false, false, false, false).await;
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
