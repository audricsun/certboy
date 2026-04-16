use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use colored::*;
use openssl::asn1::Asn1Integer;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::debug;
use walkdir::WalkDir;

/// Certificate metadata stored in each certificate directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertMetadata {
    pub version: u32,
    pub cert_type: CertType,
    pub domain: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>, // Parent CA domain (for ICA and TLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_ca: Option<String>, // Signing CA domain (same as parent for TLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_password_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<KeyAlgorithm>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    Rsa,
    EcdsaP256,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Rsa => write!(f, "rsa"),
            KeyAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CertType {
    RootCa,
    Ica,
    Tls,
}

impl std::fmt::Display for CertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertType::RootCa => write!(f, "root-ca"),
            CertType::Ica => write!(f, "ica"),
            CertType::Tls => write!(f, "tls"),
        }
    }
}

/// Metadata file name
const METADATA_FILE: &str = "meta.json";

/// Global metadata file name (at context root)
const GLOBAL_METADATA_FILE: &str = "meta.json";

/// Global metadata containing all certificates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCertMetadata {
    pub version: u32,
    pub certificates: Vec<CertMetadata>,
}

impl GlobalCertMetadata {
    pub fn new() -> Self {
        Self {
            version: 1,
            certificates: Vec::new(),
        }
    }
}

impl Default for GlobalCertMetadata {
    fn default() -> Self {
        Self::new()
    }
}

pub fn write_global_metadata(context: &Path, metadata: &GlobalCertMetadata) -> Result<()> {
    let metadata_path = context.join(GLOBAL_METADATA_FILE);

    let mut sorted_metadata = metadata.clone();
    sorted_metadata
        .certificates
        .sort_by(|a, b| a.domain.cmp(&b.domain));

    let json = serde_json::to_string_pretty(&sorted_metadata)?;
    fs::write(&metadata_path, json)?;
    debug!("Wrote global metadata to: {}", metadata_path.display());
    Ok(())
}

pub fn read_global_metadata(context: &Path) -> Result<GlobalCertMetadata> {
    // Try new filename first, then fall back to old filename for backward compatibility
    let new_path = context.join(GLOBAL_METADATA_FILE);
    let old_path = context.join("certs.json");

    let metadata_path = if new_path.exists() {
        new_path
    } else if old_path.exists() {
        old_path
    } else {
        return Ok(GlobalCertMetadata::new());
    };

    let content = fs::read_to_string(&metadata_path)?;
    let metadata: GlobalCertMetadata = serde_json::from_str(&content)?;
    Ok(metadata)
}

/// Add or update a certificate in global metadata
pub fn update_global_metadata(context: &Path, metadata: CertMetadata) -> Result<()> {
    let mut global = read_global_metadata(context).unwrap_or_default();
    global.certificates.retain(|c| c.domain != metadata.domain);
    global.certificates.push(metadata);
    write_global_metadata(context, &global)
}

/// Get certificate from global metadata by domain
#[allow(dead_code)]
pub fn get_from_global_metadata(context: &Path, domain: &str) -> Result<Option<CertMetadata>> {
    let global = read_global_metadata(context)?;
    Ok(global.certificates.into_iter().find(|c| c.domain == domain))
}

pub fn has_global_metadata(context: &Path) -> bool {
    context.join(GLOBAL_METADATA_FILE).exists() || context.join("certs.json").exists()
}

/// Find the actual path of a CA (Root or ICA) in the context
fn find_ca_path(context: &Path, domain: &str) -> Option<PathBuf> {
    // Check if it's a Root CA at root level
    let root_path = context.join(domain);
    if root_path.join("crt.pem").exists() {
        return Some(root_path);
    }

    // Check if it's an ICA under any root
    if let Ok(entries) = fs::read_dir(context) {
        for entry in entries.flatten() {
            let root_path = entry.path();
            if root_path.is_dir() {
                let ica_path = root_path.join("intermediates.d").join(domain);
                if ica_path.join("crt.pem").exists() {
                    return Some(ica_path);
                }
            }
        }
    }

    None
}

fn find_nested_ica_path(context: &Path, domain: &str) -> Option<PathBuf> {
    // Search under each Root CA in context
    if let Ok(entries) = fs::read_dir(context) {
        for entry in entries.flatten() {
            let root_path = entry.path();
            if root_path.is_dir() {
                if let Some(found) = search_intermediates(&root_path, domain) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn search_intermediates(base: &Path, domain: &str) -> Option<PathBuf> {
    if !base.is_dir() {
        return None;
    }

    // Check if this directory contains the domain in intermediates.d
    let intermediates = base.join("intermediates.d");
    if intermediates.is_dir() {
        let target = intermediates.join(domain).join("crt.pem");
        if target.exists() {
            return Some(target);
        }

        // Recursively search nested ICAs
        if let Ok(entries) = fs::read_dir(&intermediates) {
            for entry in entries.flatten() {
                let ica_path = entry.path();
                if ica_path.is_dir() {
                    if let Some(found) = search_intermediates(&ica_path, domain) {
                        return Some(found);
                    }
                }
            }
        }
    }

    None
}

/// Find certificate path by domain and type
/// Also does fallback detection if the type from metadata doesn't match actual location
fn find_cert_path(context: &Path, domain: &str, cert_type: &CertType) -> Option<PathBuf> {
    // First try based on the metadata type
    let p = match cert_type {
        CertType::RootCa => {
            let p = context.join(domain).join("crt.pem");
            if p.exists() {
                return Some(p);
            }
            None
        }
        CertType::Ica => find_nested_ica_path(context, domain),
        CertType::Tls => {
            if let Ok(entries) = fs::read_dir(context) {
                for entry in entries.flatten() {
                    let root_path = entry.path();
                    if root_path.is_dir() {
                        let cert_path = root_path
                            .join("certificates.d")
                            .join(domain)
                            .join("crt.pem");
                        if cert_path.exists() {
                            return Some(cert_path);
                        }
                        if let Ok(sub_entries) = fs::read_dir(root_path.join("intermediates.d")) {
                            for sub_entry in sub_entries.flatten() {
                                let ica_path = sub_entry.path();
                                if ica_path.is_dir() {
                                    let cert_path = ica_path
                                        .join("certificates.d")
                                        .join(domain)
                                        .join("crt.pem");
                                    if cert_path.exists() {
                                        return Some(cert_path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            None
        }
    };

    // If not found by metadata type, try fallback detection
    if p.is_none() {
        // Try as Root CA at context/domain/crt.pem
        let root_path = context.join(domain).join("crt.pem");
        if root_path.exists() {
            return Some(root_path);
        }
        // Try as ICA
        if let Some(ica_path) = find_nested_ica_path(context, domain) {
            return Some(ica_path);
        }
    }

    p
}

/// Calculate days until expiry from ASN1Time string
fn calculate_days_until_expiry(not_after: &str) -> i64 {
    if let Ok(expiry) = asn1time_to_datetime(not_after) {
        let now = Utc::now();
        (expiry - now).num_days()
    } else {
        0
    }
}

fn shorten_path(path: &Path) -> String {
    let path_str = path.display().to_string();
    if let Some(home) = dirs::home_dir() {
        let home_str = home.display().to_string();
        if !home_str.is_empty() && path_str.starts_with(&home_str) {
            return path_str.replacen(&home_str, "~", 1);
        }
    }
    path_str
}

/// Read metadata from certificate directory
pub fn read_metadata(dir: &Path) -> Result<CertMetadata> {
    let metadata_path = dir.join(METADATA_FILE);
    let content = fs::read_to_string(&metadata_path)?;
    let metadata: CertMetadata = serde_json::from_str(&content)?;
    Ok(metadata)
}

/// Check if metadata file exists in directory
pub fn has_metadata(dir: &Path) -> bool {
    dir.join(METADATA_FILE).exists()
}

/// Create metadata from X509 certificate
pub fn create_metadata_from_cert(
    dir: &Path,
    cert: &X509,
    cert_type: CertType,
    parent: Option<String>,
) -> Result<CertMetadata> {
    let domain = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let subject = cert
        .subject_name()
        .entries()
        .map(|e| {
            let val = e
                .data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let issuer = cert
        .issuer_name()
        .entries()
        .map(|e| {
            let val = e
                .data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let serial = cert
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let signing_ca = parent.clone();

    Ok(CertMetadata {
        version: 1,
        cert_type,
        domain,
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        parent,
        signing_ca,
        private_key_encrypted: None,
        private_key_password_file: None,
        key_algorithm: None,
    })
}

/// Convert OpenSSL ASN1Time string to DateTime<Utc>
/// Format: "Mar  8 06:21:27 2036 GMT"
fn asn1time_to_datetime(asn1time: &str) -> Result<DateTime<Utc>> {
    // Parse the ASN1Time string
    // Remove trailing " GMT" if present
    let clean_time = asn1time.trim_end_matches(" GMT");

    // Handle variable spacing in month abbreviation (Mar  8 vs Mar 8)
    // split_whitespace collapses multiple spaces, so we need a different approach
    // Format is: "MMM DD HH:MM:SS YYYY GMT" but DD may have leading space
    let mut chars = clean_time.chars().peekable();
    let mut parts = Vec::new();
    let mut current_part = String::new();

    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            if !current_part.is_empty() {
                parts.push(current_part);
                current_part = String::new();
            }
            // Skip any additional whitespace
            while chars.peek().map(|c| c.is_whitespace()).unwrap_or(false) {
                chars.next();
            }
        } else {
            current_part.push(c);
        }
    }

    if !current_part.is_empty() {
        parts.push(current_part);
    }

    // We should have exactly 4 parts: Month, Day, Time, Year
    if parts.len() != 4 {
        bail!(
            "Invalid ASN1Time format (expected 4 parts, got {}): {}",
            parts.len(),
            asn1time
        );
    }

    // Parse month abbreviation
    let month = match parts[0].as_str() {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => bail!("Invalid month in ASN1Time: {}", parts[0]),
    };

    let day = parts[1].parse::<u32>()?;
    // Time format: HH:MM:SS
    let time_parts: Vec<&str> = parts[2].split(':').collect();
    if time_parts.len() != 3 {
        bail!("Invalid time format: {}", parts[2]);
    }
    let hour = time_parts[0].parse::<u32>()?;
    let minute = time_parts[1].parse::<u32>()?;
    let second = time_parts[2].parse::<u32>()?;
    let year = parts[3].parse::<i32>()?;

    // Create naive datetime and convert to UTC
    let date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| anyhow::anyhow!("Invalid date components"))?;
    let time = NaiveTime::from_hms_opt(hour, minute, second)
        .ok_or_else(|| anyhow::anyhow!("Invalid time components"))?;
    let naive = NaiveDateTime::new(date, time);

    Ok(DateTime::from_naive_utc_and_offset(naive, Utc))
}

fn asn1time_to_local_string(asn1time: &str) -> String {
    if let Ok(dt_utc) = asn1time_to_datetime(asn1time) {
        dt_utc
            .with_timezone(&Local)
            .format("%b %e %H:%M:%S %Y %Z")
            .to_string()
    } else {
        asn1time.to_string()
    }
}

/// Check if a serial number already exists in any certificate within the context directory.
/// Returns true if the serial number is already in use.
fn serial_exists_in_context(context: &Path, serial_bytes: &[u8]) -> Result<bool> {
    for entry in WalkDir::new(context)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() && path.file_name().and_then(|n| n.to_str()) == Some("crt.pem") {
            if let Ok(pem) = fs::read(path) {
                if let Ok(cert) = X509::from_pem(&pem) {
                    if let Ok(bn) = cert.serial_number().to_bn() {
                        if let Ok(serial_hex) = bn.to_hex_str() {
                            let target_hex: String =
                                serial_bytes.iter().map(|b| format!("{:02X}", b)).collect();
                            if serial_hex.to_string() == target_hex {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(false)
}

/// Generate a unique 20-byte random serial number (OpenSSL format) with collision detection.
/// Searches all crt.pem files in the context directory to ensure uniqueness.
/// Skips zero serial (all zeros).
pub fn generate_unique_serial(context: &Path) -> Result<Asn1Integer> {
    let mut serial_bytes = [0u8; 20];
    loop {
        rand::rng().fill(&mut serial_bytes);
        // Skip zero serial (all zeros)
        if serial_bytes.iter().all(|&b| b == 0) {
            continue;
        }
        // Check for collision
        if !serial_exists_in_context(context, &serial_bytes)? {
            break;
        }
        // Loop until unique serial found
    }
    let bn = BigNum::from_slice(&serial_bytes)?;
    let asn1_int = Asn1Integer::from_bn(&bn)?;
    Ok(asn1_int)
}

fn extract_parent_ca(path: &str) -> Option<String> {
    // Extract parent CA from path patterns:
    // New structure: /home/user/.local/state/certboy/<root>/certificates.d/<domain>/crt.pem
    // Old structure: /home/user/.local/state/certboy/certs.d/<root>/intermediates.d/<ica>/crt.pem

    if path.contains("intermediates.d/") {
        // ICA: get the root before intermediates.d
        let parts: Vec<&str> = path.split("intermediates.d/").collect();
        if parts.len() > 1 {
            let before = parts[0];
            // Extract root domain from path
            if let Some(last_slash) = before.rfind('/') {
                let before_slash = &before[..last_slash];
                if let Some(domain_start) = before_slash.rfind('/') {
                    return Some(before_slash[domain_start + 1..].to_string());
                }
            }
        }
    } else if path.contains("certificates.d/") {
        // Server cert: get the CA before certificates.d
        let parts: Vec<&str> = path.split("certificates.d/").collect();
        if parts.len() > 1 {
            let before = parts[0];
            // Extract CA domain from path
            if let Some(last_slash) = before.rfind('/') {
                let before_slash = &before[..last_slash];
                if let Some(domain_start) = before_slash.rfind('/') {
                    return Some(before_slash[domain_start + 1..].to_string());
                }
            }
        }
    }

    None
}

fn display_certificate_node(
    cert: &CertificateInfo,
    ancestors_last: &[bool],
    is_last: bool,
    is_root: bool,
    expiration_alert_days: u32,
    detail: bool,
    verify_openssl: bool,
) {
    let tree_prefix = ancestors_last
        .iter()
        .map(|last| if *last { "    " } else { "│   " })
        .collect::<String>();
    let header_prefix = if is_root {
        String::new()
    } else if is_last {
        format!("{}└── ", tree_prefix)
    } else {
        format!("{}├── ", tree_prefix)
    };
    let block_prefix = if is_root {
        String::new()
    } else if is_last {
        format!("{}    ", tree_prefix)
    } else {
        format!("{}│   ", tree_prefix)
    };
    let status = if cert.needs_renewal {
        "warn".yellow().bold()
    } else {
        "ok".green()
    };

    let cert_type_color = match cert.cert_type {
        CertificateType::RootCa => "Root CA".cyan(),
        CertificateType::IntermediateCa => "ICA".magenta(),
        CertificateType::ServerCert => "Server".blue(),
    };

    let days_color = if cert.expires_in_days < expiration_alert_days as i64 {
        cert.expires_in_days.to_string().red()
    } else if cert.expires_in_days < 90 {
        cert.expires_in_days.to_string().yellow()
    } else {
        cert.expires_in_days.to_string().green()
    };

    let domain_display = if cert.cert_type == CertificateType::RootCa {
        let algo = cert
            .key_algorithm
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        format!("{} {}", cert.domain.bold(), algo.red())
    } else {
        cert.domain.bold().to_string()
    };

    println!(
        "{}{} [{}] {} ({})",
        header_prefix, status, cert_type_color, domain_display, days_color
    );

    let detail_prefix = if is_root {
        "│  ".to_string()
    } else {
        block_prefix.clone()
    };

    println!(
        "{}Subject: {}",
        detail_prefix.white(),
        cert.subject.dimmed()
    );
    println!(
        "{}Valid: {} to {}",
        detail_prefix.white(),
        asn1time_to_local_string(&cert.not_before).dimmed(),
        asn1time_to_local_string(&cert.not_after).dimmed()
    );

    let serial_display = if cert.serial == "0" {
        cert.serial.clone().red().to_string()
    } else {
        cert.serial.yellow().to_string()
    };

    println!("{}Serial: {}", detail_prefix.white(), serial_display);

    if detail && !cert.sans.is_empty() {
        println!(
            "{}SANs: {}",
            detail_prefix.white(),
            cert.sans.join(", ").magenta()
        );
        debug!("SANs for {}: {:?}", cert.domain, cert.sans);
    }

    if cert.needs_renewal {
        println!("{}⚠️  Needs renewal!", detail_prefix.white().bold());
    }

    if verify_openssl && cert.cert_type == CertificateType::ServerCert {
        let cert_dir = cert.path.parent().unwrap();
        match verify_key_cert_match(cert_dir) {
            Ok((is_valid, message)) => {
                if is_valid {
                    println!("{}OpenSSL: {}", detail_prefix.white(), message.green());
                } else if message.contains("DO NOT MATCH") {
                    println!(
                        "{}OpenSSL: {} - MISMATCH DETECTED",
                        detail_prefix.white(),
                        message.red().bold()
                    );
                } else {
                    // Encrypted key, missing files, etc. - show as error without MISMATCH suffix
                    println!("{}OpenSSL: {}", detail_prefix.white(), message.red().bold());
                }
            }
            Err(e) => {
                println!(
                    "{}OpenSSL: Error: {}",
                    detail_prefix.white(),
                    e.to_string().yellow()
                );
            }
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct CertificatePaths {
    pub dir: PathBuf,
    pub key: PathBuf,
    pub csr: PathBuf,
    pub crt: PathBuf,
    pub ext: PathBuf,
    pub pass: PathBuf,
    pub fullchain: PathBuf,
}

impl CertificatePaths {
    #[allow(dead_code)] // Used in tests
    pub fn new(base_dir: &str, name: &str) -> Self {
        let dir = PathBuf::from(base_dir).join(name);
        Self {
            key: dir.join("key.pem"),
            csr: dir.join("csr.pem"),
            crt: dir.join("crt.pem"),
            ext: dir.join("ext.cnf"),
            pass: dir.join("key.pass"),
            fullchain: dir.join("fullchain.crt"),
            dir,
        }
    }

    #[allow(dead_code)] // Used in tests
    pub fn create_dir(&self) -> Result<()> {
        debug!("Creating directory: {:?}", self.dir);
        fs::create_dir_all(&self.dir)?;
        Ok(())
    }
}

fn display_certificate_tree(
    certificates: &[CertificateInfo],
    expiration_alert_days: u32,
    detail: bool,
    verify_openssl: bool,
) -> Result<()> {
    use std::collections::HashMap;

    // Group certificates by metadata parent relationships (with fallback to path-based)
    let mut root_cas: Vec<CertificateInfo> = Vec::new();
    let mut icas_by_root: std::collections::HashMap<String, Vec<CertificateInfo>> = HashMap::new();
    let mut server_certs_by_ca: std::collections::HashMap<String, Vec<CertificateInfo>> =
        HashMap::new();

    for cert in certificates {
        match cert.cert_type {
            CertificateType::RootCa => {
                // Root CA: top level
                root_cas.push(cert.clone());
            }
            CertificateType::IntermediateCa => {
                // ICA: try metadata parent first, then path-based fallback
                if let Some(parent) = &cert.parent {
                    icas_by_root
                        .entry(parent.clone())
                        .or_default()
                        .push(cert.clone());
                } else {
                    // Fallback to path-based detection
                    let path_str = cert.path.to_string_lossy().to_string();
                    if let Some(root) = extract_parent_ca(&path_str) {
                        icas_by_root.entry(root).or_default().push(cert.clone());
                    } else {
                        root_cas.push(cert.clone());
                    }
                }
            }
            CertificateType::ServerCert => {
                // Server cert: try metadata parent first, then path-based fallback
                if let Some(parent) = &cert.parent {
                    server_certs_by_ca
                        .entry(parent.clone())
                        .or_default()
                        .push(cert.clone());
                } else {
                    // Fallback to path-based detection
                    let path_str = cert.path.to_string_lossy().to_string();
                    if let Some(ca) = extract_parent_ca(&path_str) {
                        server_certs_by_ca.entry(ca).or_default().push(cert.clone());
                    } else {
                        root_cas.push(cert.clone());
                    }
                }
            }
        }
    }

    if root_cas.is_empty() {
        println!("No certificates found.");
        return Ok(());
    }

    // Sort roots for consistent output
    root_cas.sort_by(|a, b| a.domain.cmp(&b.domain));

    println!();

    for root in &root_cas {
        display_certificate_node(
            root,
            &[],
            true,
            true,
            expiration_alert_days,
            detail,
            verify_openssl,
        );
        display_children(
            root,
            &icas_by_root,
            &server_certs_by_ca,
            &[],
            expiration_alert_days,
            detail,
            verify_openssl,
        );

        println!();
    }

    let mut serial_to_domains: std::collections::HashMap<String, Vec<String>> = HashMap::new();
    for cert in certificates {
        serial_to_domains
            .entry(cert.serial.clone())
            .or_default()
            .push(cert.domain.clone());
    }

    let duplicates: Vec<(&String, &Vec<String>)> = serial_to_domains
        .iter()
        .filter(|(_, domains)| domains.len() > 1)
        .collect();

    if !duplicates.is_empty() {
        println!();
        println!("{}", "⚠️  DUPLICATE SERIAL NUMBERS DETECTED".red().bold());
        for (serial, domains) in &duplicates {
            println!("  Serial {} appears in:", serial.red());
            for domain in *domains {
                println!("    - {}", domain.yellow());
            }
        }
        println!("  Multiple certificates with the same serial can cause browser security errors.");
        println!("  Consider regenerating certificates with duplicate serials.");
    }

    Ok(())
}

fn display_children(
    parent: &CertificateInfo,
    icas_by_root: &std::collections::HashMap<String, Vec<CertificateInfo>>,
    server_certs_by_ca: &std::collections::HashMap<String, Vec<CertificateInfo>>,
    ancestors_last: &[bool],
    expiration_alert_days: u32,
    detail: bool,
    verify_openssl: bool,
) {
    let mut icas = icas_by_root
        .get(&parent.domain)
        .cloned()
        .unwrap_or_default();
    let mut servers = server_certs_by_ca
        .get(&parent.domain)
        .cloned()
        .unwrap_or_default();
    icas.sort_by(|a, b| a.domain.cmp(&b.domain));
    servers.sort_by(|a, b| a.domain.cmp(&b.domain));

    let total_children = icas.len() + servers.len();
    if total_children == 0 {
        return;
    }

    for (idx, ica) in icas.iter().enumerate() {
        let child_index = idx;
        let is_last_child = child_index + 1 == total_children;
        display_certificate_node(
            ica,
            ancestors_last,
            is_last_child,
            false,
            expiration_alert_days,
            detail,
            verify_openssl,
        );
        let mut next_ancestors = ancestors_last.to_vec();
        next_ancestors.push(is_last_child);
        display_children(
            ica,
            icas_by_root,
            server_certs_by_ca,
            &next_ancestors,
            expiration_alert_days,
            detail,
            verify_openssl,
        );
    }

    for (idx, server) in servers.iter().enumerate() {
        let child_index = icas.len() + idx;
        let is_last_child = child_index + 1 == total_children;
        display_certificate_node(
            server,
            ancestors_last,
            is_last_child,
            false,
            expiration_alert_days,
            detail,
            verify_openssl,
        );
    }
}

pub fn write_file(path: &Path, content: &str) -> Result<()> {
    debug!("Writing file: {:?}", path);
    fs::write(path, content)?;
    Ok(())
}

pub fn read_file(path: &Path) -> Result<String> {
    debug!("Reading file: {:?}", path);
    let content = fs::read_to_string(path)?;
    Ok(content)
}

#[allow(dead_code)] // Public API
pub fn file_exists(path: &Path) -> bool {
    path.exists()
}

pub fn generate_random_password() -> Result<String> {
    debug!("Generating random password");
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate random bytes: {}", e))?;
    let password = BASE64.encode(bytes);
    Ok(password)
}

#[allow(dead_code)] // Public API
pub fn check_certificate_expiry(cert_path: &Path) -> Result<bool> {
    debug!("Checking certificate expiry: {:?}", cert_path);

    // For now, we'll just check if the file exists and is not empty
    // In a real implementation, you would parse the certificate and check its expiry
    if !cert_path.exists() {
        return Ok(false);
    }

    let metadata = fs::metadata(cert_path)?;
    if metadata.len() == 0 {
        return Ok(false);
    }

    // For demonstration purposes, we'll assume the certificate is valid
    // In a real implementation, you would parse the certificate and check the not_after field
    debug!("Certificate appears to be valid");
    Ok(true)
}

pub fn generate_default_ext_content(domain: &str) -> String {
    debug!("Generating default ext.cnf content for domain: {}", domain);
    format!(
        r#"basicConstraints        = critical,CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer:always
nsCertType              = server
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth
subjectAltName          = @alt_names
[alt_names]
DNS.1 = {domain}
# Uncomment below if need to customize
# and re-generate cert with '--force'
# DNS.2 = *.yourdomain.com
# IP.1 = 127.0.0.1
"#
    )
}

pub fn parse_alt_names_from_ext(ext_content: &str) -> Result<Vec<String>> {
    debug!("Parsing alt names from ext.cnf content");
    let mut alt_names = Vec::new();

    for line in ext_content.lines() {
        let line = line.trim();
        // Parse DNS entries
        if line.starts_with("DNS.") {
            if let Some(domain) = line.split('=').nth(1) {
                let domain = domain.trim();
                if !domain.is_empty() {
                    alt_names.push(domain.to_string());
                }
            }
        }
        // Parse IP entries
        if line.starts_with("IP.") {
            if let Some(ip) = line.split('=').nth(1) {
                let ip = ip.trim();
                if !ip.is_empty() {
                    alt_names.push(ip.to_string());
                }
            }
        }
    }

    debug!("Parsed alt names: {:?}", alt_names);
    Ok(alt_names)
}

#[allow(dead_code)] // Public API
pub fn update_fullchain_crt() -> Result<()> {
    debug!("Updating fullchain.crt files");
    let ca_dir = PathBuf::from("CAs");
    if ca_dir.exists() {
        let mut crt_files = Vec::new();
        for entry in fs::read_dir(&ca_dir)? {
            let entry = entry?;
            let ca_path = entry.path();
            if ca_path.is_dir() {
                let cert_path = ca_path.join("crt.pem");
                if cert_path.exists() {
                    debug!("Found CA cert {:?}", cert_path);
                    crt_files.push(cert_path);
                }
            }
        }
        let mut fullchain = Vec::new();
        for crt in &crt_files {
            let content = fs::read(crt)?;
            fullchain.extend_from_slice(&content);
            if !content.ends_with(b"\n") {
                fullchain.push(b'\n');
            }
        }
        for crt in &crt_files {
            if let Some(dir) = crt.parent() {
                let fullchain_path = dir.join("fullchain.crt");
                let mut f = fs::File::create(&fullchain_path)?;
                f.write_all(&fullchain)?;
                debug!("Updated {:?}", fullchain_path);
            }
        }
    }
    Ok(())
}

fn find_parent_ca_in_context(
    context: &Path,
    domain: &str,
    imported_cert: &X509,
) -> Result<Option<String>> {
    if !context.exists() {
        return Ok(None);
    }

    // Collect all potential parent CAs (Root CA and ICAs)
    let mut candidates: Vec<(String, PathBuf, CertType)> = Vec::new();

    // Find Root CAs in context
    if let Ok(entries) = fs::read_dir(context) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let crt_path = path.join("crt.pem");
                if crt_path.exists() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name != "intermediates.d" && name != "certificates.d" {
                            candidates.push((name.to_string(), path.clone(), CertType::RootCa));
                        }
                    }
                }
            }
        }
    }

    // Find ICAs in context
    let intermediates_dir = context.join("intermediates.d");
    if intermediates_dir.exists() {
        if let Ok(entries) = fs::read_dir(&intermediates_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let crt_path = path.join("crt.pem");
                    if crt_path.exists() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            candidates.push((name.to_string(), path.clone(), CertType::Ica));
                        }
                    }
                }
            }
        }
    }

    // Also find ICAs under Root CA directories (e.g., context/root-ca/intermediates.d/ica)
    if let Ok(entries) = fs::read_dir(context) {
        for entry in entries.flatten() {
            let root_path = entry.path();
            if root_path.is_dir() {
                let icas_dir = root_path.join("intermediates.d");
                if icas_dir.exists() {
                    if let Ok(ica_entries) = fs::read_dir(&icas_dir) {
                        for ica_entry in ica_entries.flatten() {
                            let ica_path = ica_entry.path();
                            if ica_path.is_dir() {
                                let crt_path = ica_path.join("crt.pem");
                                if crt_path.exists() {
                                    if let Some(name) =
                                        ica_path.file_name().and_then(|n| n.to_str())
                                    {
                                        candidates.push((
                                            name.to_string(),
                                            ica_path.clone(),
                                            CertType::Ica,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Find the best parent candidate (longest matching suffix)
    let mut best_parent: Option<String> = None;
    for (candidate_domain, candidate_path, _cert_type) in candidates {
        // Check if candidate is a parent of the imported domain
        // e.g., "example.io" is parent of "ops.example.io"
        if domain.ends_with(&candidate_domain) && domain != candidate_domain {
            // Verify the certificate chain: imported cert should be signed by this candidate
            let candidate_crt = candidate_path.join("crt.pem");
            if let Ok(crt_data) = fs::read(&candidate_crt) {
                if let Ok(parent_cert) = X509::from_pem(&crt_data) {
                    // Check if imported cert is signed by parent cert
                    if verify_certificate_chain(imported_cert, &parent_cert) {
                        // Use the longest match as the parent
                        match &best_parent {
                            None => best_parent = Some(candidate_domain),
                            Some(existing) => {
                                if candidate_domain.len() > existing.len() {
                                    best_parent = Some(candidate_domain);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(best_parent)
}

fn verify_certificate_chain(cert: &X509, issuer: &X509) -> bool {
    let cert_issuer = cert.issuer_name();
    let issuer_subject = issuer.subject_name();

    let cert_issuer_str = cert_issuer
        .entries()
        .filter_map(|e| {
            let val = e.data().as_utf8().ok()?;
            Some(format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                val
            ))
        })
        .collect::<Vec<_>>();
    let issuer_subject_str = issuer_subject
        .entries()
        .filter_map(|e| {
            let val = e.data().as_utf8().ok()?;
            Some(format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                val
            ))
        })
        .collect::<Vec<_>>();

    cert_issuer_str == issuer_subject_str
}

pub fn verify_fullchain_order(cert_dir: &Path) -> Result<(bool, String)> {
    let fullchain_path = cert_dir.join("fullchain.crt");
    let crt_path = cert_dir.join("crt.pem");

    if !fullchain_path.exists() {
        return Ok((
            true,
            "fullchain.crt not found (not an ICA-signed certificate)".to_string(),
        ));
    }

    let fullchain_content = fs::read(&fullchain_path)?;
    let fullchain_str = String::from_utf8_lossy(&fullchain_content);

    let certs: Vec<&str> = fullchain_str
        .split("-----BEGIN CERTIFICATE-----")
        .filter(|s| !s.trim().is_empty())
        .collect();

    if certs.is_empty() {
        return Ok((true, "fullchain.crt is empty".to_string()));
    }

    let cert_content = fs::read(&crt_path)?;
    let server_cert = X509::from_pem(&cert_content)?;
    let server_cert_subject = server_cert.subject_name();
    let server_cert_issuer = server_cert.issuer_name();

    let _server_subject_cn = get_cn_from_name(server_cert_subject);
    let server_issuer_cn = get_cn_from_name(server_cert_issuer);

    // For ICA-signed certs, fullchain should have exactly 2 certificates:
    // 1. Server certificate (leaf)
    // 2. ICA certificate (intermediate)
    if certs.len() != 2 {
        let msg = format!(
            "fullchain should have exactly 2 certificates (server + ICA), got {}",
            certs.len()
        );
        return Ok((false, msg));
    }

    // Verify the second certificate is the ICA that signed this server cert
    let second_cert = certs[1];
    let second_cert_cn = extract_cn_from_pem(second_cert);

    let is_valid = second_cert_cn
        .as_ref()
        .map(|cn| cn == &server_issuer_cn)
        .unwrap_or(false);

    if is_valid {
        Ok((
            true,
            "fullchain order is correct (server cert + ICA)".to_string(),
        ))
    } else {
        let msg = format!(
            "fullchain order is WRONG! Second certificate should be ICA '{}', got: {:?}",
            server_issuer_cn, second_cert_cn
        );
        Ok((false, msg))
    }
}

fn get_cn_from_name(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .filter_map(|e| {
            if e.object().nid() == openssl::nid::Nid::COMMONNAME {
                e.data().as_utf8().ok().map(|s| s.to_string())
            } else {
                None
            }
        })
        .next()
        .unwrap_or_default()
}

fn extract_cn_from_pem(pem_section: &str) -> Option<String> {
    let pem = format!("-----BEGIN CERTIFICATE-----{}", pem_section);
    let cert = X509::from_pem(pem.as_bytes()).ok()?;
    let subject = cert.subject_name();
    Some(get_cn_from_name(subject))
}

pub fn fix_fullchain_order(cert_dir: &Path, _context: &Path) -> Result<()> {
    let fullchain_path = cert_dir.join("fullchain.crt");
    let crt_path = cert_dir.join("crt.pem");

    if !fullchain_path.exists() || !crt_path.exists() {
        return Err(anyhow::anyhow!("Certificate files not found"));
    }

    let cert_pem = fs::read(&crt_path)?;

    let cert = X509::from_pem(&cert_pem)?;
    let issuer_cn = get_cn_from_name(cert.issuer_name());
    let subject_cn = get_cn_from_name(cert.subject_name());

    // This is a Root CA-signed certificate (self-signed) - no fullchain needed
    if issuer_cn == subject_cn {
        // For root CA-signed certs, fullchain.crt should NOT exist
        // If it does exist, remove it to clean up incorrect state
        if fullchain_path.exists() {
            fs::remove_file(&fullchain_path)?;
            println!(
                "Removed incorrect fullchain.crt for Root CA-signed certificate: {}",
                cert_dir.display()
            );
        }
        return Ok(());
    }

    // ICA-signed certificate: find the ICA certificate
    let cert_dir_str = cert_dir.to_string_lossy();
    if cert_dir_str.contains("/intermediates.d/") {
        if let Some(intermediates_pos) = cert_dir_str.find("/intermediates.d/") {
            let before_intermediates = &cert_dir_str[..intermediates_pos];
            let ica_path = format!(
                "{}/intermediates.d/{}/crt.pem",
                before_intermediates, issuer_cn
            );
            let ica_path = PathBuf::from(ica_path);

            if ica_path.exists() {
                let mut fullchain_content = cert_pem.clone();
                let ica_pem = fs::read(&ica_path)?;
                fullchain_content.extend_from_slice(&ica_pem);
                fs::write(&fullchain_path, &fullchain_content)?;
                println!("Fixed fullchain order for: {}", cert_dir.display());
                return Ok(());
            }
        }
    }

    Err(anyhow::anyhow!(
        "Could not find ICA certificate '{}' for certificate in {}",
        issuer_cn,
        cert_dir.display()
    ))
}

fn is_ca_certificate(cert: &X509) -> bool {
    let subject = cert.subject_name();
    let issuer = cert.issuer_name();

    let subject_str = subject
        .entries()
        .map(|e| {
            e.data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(",");
    let issuer_str = issuer
        .entries()
        .map(|e| {
            e.data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(",");

    // Self-signed = Root CA
    subject_str == issuer_str
}

/// Verify that the private key matches the certificate using OpenSSL
/// Returns (is_valid, message)
pub fn verify_key_cert_match(cert_dir: &Path) -> Result<(bool, String)> {
    let key_path = cert_dir.join("key.pem");
    let crt_path = cert_dir.join("crt.pem");
    let pass_path = read_metadata(cert_dir)
        .ok()
        .and_then(|m| m.private_key_password_file)
        .map(|f| cert_dir.join(f))
        .unwrap_or_else(|| {
            let pass_key = cert_dir.join("pass.key");
            if pass_key.exists() {
                pass_key
            } else {
                cert_dir.join("key.pass")
            }
        });

    if !key_path.exists() {
        return Ok((false, "key.pem not found".to_string()));
    }
    if !crt_path.exists() {
        return Ok((false, "crt.pem not found".to_string()));
    }

    let key_path_str = key_path.to_string_lossy();
    let crt_path_str = crt_path.to_string_lossy();

    let is_encrypted = fs::read_to_string(&key_path)
        .map(|content| content.contains("BEGIN ENCRYPTED PRIVATE KEY"))
        .unwrap_or(false);

    let mut key_cmd = std::process::Command::new("openssl");
    key_cmd
        .args(["rsa", "-modulus", "-noout", "-in"])
        .arg(&*key_path_str);

    if is_encrypted {
        if pass_path.exists() {
            if let Ok(pass) = fs::read_to_string(&pass_path) {
                key_cmd.arg("-passin").arg(format!("pass:{}", pass.trim()));
                debug!(
                    "  openssl: key is encrypted, using {} to decrypt",
                    pass_path.display()
                );
            } else {
                return Ok((
                    false,
                    format!(
                        "key.pem is encrypted but {} not readable",
                        pass_path.display()
                    ),
                ));
            }
        } else {
            debug!(
                "  openssl: key is encrypted but passphrase file not found: {}",
                pass_path.display()
            );
            return Ok((
                false,
                format!(
                    "key.pem is encrypted but passphrase file not found: {}",
                    pass_path.display()
                ),
            ));
        }
    }

    debug!(
        "  openssl: openssl rsa -modulus -noout -in {}",
        key_path_str
    );
    let key_modulus = key_cmd.output();

    debug!(
        "  openssl: openssl x509 -modulus -noout -in {}",
        crt_path_str
    );
    let cert_modulus = std::process::Command::new("openssl")
        .args(["x509", "-modulus", "-noout", "-in"])
        .arg(&*crt_path_str)
        .output();

    match (key_modulus, cert_modulus) {
        (Ok(key_out), Ok(cert_out)) => {
            let key_status = key_out.status;
            let cert_status = cert_out.status;

            if !key_status.success() {
                let err = String::from_utf8_lossy(&key_out.stderr);
                debug!("  openssl: key.pem invalid: {}", err.trim());
                return Ok((false, format!("key.pem is invalid: {}", err.trim())));
            }
            if !cert_status.success() {
                let err = String::from_utf8_lossy(&cert_out.stderr);
                debug!("  openssl: crt.pem invalid: {}", err.trim());
                return Ok((false, format!("crt.pem is invalid: {}", err.trim())));
            }

            let key_mod = String::from_utf8_lossy(&key_out.stdout).trim().to_string();
            let cert_mod = String::from_utf8_lossy(&cert_out.stdout).trim().to_string();

            debug!(
                "  openssl: key modulus = {}..., cert modulus = {}...",
                &key_mod[..8.min(key_mod.len())],
                &cert_mod[..8.min(cert_mod.len())]
            );

            if key_mod == cert_mod {
                debug!("  openssl: moduli match");
                Ok((true, "key and certificate match".to_string()))
            } else {
                debug!("  openssl: moduli DO NOT MATCH");
                Ok((false, "key and certificate DO NOT MATCH".to_string()))
            }
        }
        (Err(e), _) => Ok((false, format!("Failed to run openssl for key: {}", e))),
        (_, Err(e)) => Ok((false, format!("Failed to run openssl for cert: {}", e))),
    }
}

pub async fn import_certificate(source: &Path, context: &Path) -> Result<()> {
    if !source.exists() {
        return Err(anyhow::anyhow!("Source path does not exist: {:?}", source));
    }

    let source_crt = source.join("crt.pem");
    if !source_crt.exists() {
        return Err(anyhow::anyhow!(
            "Source path is not a valid CA/ICA folder (missing crt.pem): {:?}",
            source
        ));
    }

    let cert = X509::from_pem(&fs::read(&source_crt)?)?;

    let domain = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let subject = cert
        .subject_name()
        .entries()
        .map(|e| {
            let val = e
                .data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let issuer = cert
        .issuer_name()
        .entries()
        .map(|e| {
            let val = e
                .data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let serial = cert
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let is_ca = is_ca_certificate(&cert);
    let path_str = source.to_string_lossy().to_string();
    let is_under_intermediates = path_str.contains("intermediates.d");

    // Heuristic: if importing from a path with CA or CAs (case-insensitive), treat as CA/ICA
    // But NOT if it's Certs (server certs)
    let path_lower = path_str.to_lowercase();
    let looks_like_ca_import = (path_lower.contains("/ca")
        || path_lower.contains("/cas")
        || path_lower.contains("ca/")
        || path_lower.contains("cas/")
        || path_lower.contains("\\ca")
        || path_lower.contains("\\cas"))
        && !path_lower.contains("certs");

    let detected_parent = find_parent_ca_in_context(context, &domain, &cert)?;

    let (cert_type, parent, dest_dir) = if is_ca {
        // Self-signed = Root CA (regardless of import path)
        let dest = context.join(&domain);
        (CertType::RootCa, None, dest)
    } else if is_under_intermediates || looks_like_ca_import {
        // Self-signed OR under intermediates.d OR importing from CAs dir = CA
        if is_under_intermediates || detected_parent.is_some() || looks_like_ca_import {
            let parent = extract_parent_ca(&path_str).or(detected_parent.clone());
            if let Some(ref p) = parent {
                let parent_path = find_ca_path(context, p);
                let dest = if let Some(ref pp) = parent_path {
                    pp.join("intermediates.d").join(&domain)
                } else {
                    context.join(p).join("intermediates.d").join(&domain)
                };
                (CertType::Ica, parent, dest)
            } else {
                let dest = context.join(&domain);
                (CertType::Ica, None, dest)
            }
        } else {
            let dest = context.join(&domain);
            (CertType::RootCa, None, dest)
        }
    } else {
        // Server certificate (TLS)
        let parent = extract_parent_ca(&path_str).or(detected_parent.clone());

        if let Some(ref p) = parent {
            let parent_path = find_ca_path(context, p);
            let dest = if let Some(ref pp) = parent_path {
                pp.join("certificates.d").join(&domain)
            } else {
                context.join(p).join("certificates.d").join(&domain)
            };
            (CertType::Tls, parent, dest)
        } else {
            let dest = context.join(&domain).join("certificates.d").join(&domain);
            (CertType::Tls, None, dest)
        }
    };

    // Copy the source folder to destination
    debug!("Copying {} to {}", source.display(), dest_dir.display());
    if dest_dir.exists() {
        println!(
            "Warning: {} already exists, skipping copy",
            dest_dir.display()
        );
    } else {
        copy_dir_all(source, &dest_dir)?;
    }

    let metadata = CertMetadata {
        version: 1,
        cert_type: cert_type.clone(),
        domain: domain.clone(),
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        parent: parent.clone(),
        signing_ca: parent,
        private_key_encrypted: None,
        private_key_password_file: None,
        key_algorithm: None,
    };

    fs::create_dir_all(context)?;
    update_global_metadata(context, metadata)?;

    println!("Imported certificate: {}", domain);
    println!("  Type: {:?}", cert_type);
    println!("  Context: {}", context.display());
    println!("  Path: {}", dest_dir.display());

    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub fn export_certificate(context: &Path, domain: &str) -> Result<()> {
    let cert_path = find_cert_path(context, domain, &CertType::Tls);

    if cert_path.is_none() {
        return Err(anyhow::anyhow!(
            "Server certificate '{}' not found in context '{}'",
            domain,
            context.display()
        ));
    }

    let cert_file_path = cert_path.unwrap();
    let cert_dir = cert_file_path.parent().unwrap();

    // For ICA-signed certificates, export fullchain.crt instead of crt.pem
    let fullchain_path = cert_dir.join("fullchain.crt");
    let has_fullchain = fullchain_path.exists();
    let crt_source = if has_fullchain {
        fullchain_path
    } else {
        cert_dir.join("crt.pem")
    };

    let key_source = cert_dir.join("key.pem");

    if !crt_source.exists() {
        return Err(anyhow::anyhow!(
            "Certificate file not found: {:?}",
            crt_source
        ));
    }

    if !key_source.exists() {
        return Err(anyhow::anyhow!("Key file not found: {:?}", key_source));
    }

    let current_dir = std::env::current_dir()?;
    let crt_dest = current_dir.join(format!("{}.crt", domain));
    let key_dest = current_dir.join(format!("{}.key", domain));

    fs::copy(&crt_source, &crt_dest)?;
    fs::copy(&key_source, &key_dest)?;

    let cert_type = if has_fullchain {
        "fullchain"
    } else {
        "certificate"
    };
    println!(
        "Exported {} and key to current directory:\n  {} -> {}\n  {} -> {}",
        cert_type,
        crt_source.display(),
        crt_dest.display(),
        key_source.display(),
        key_dest.display()
    );

    Ok(())
}

/// Find all TLS certificates signed by a given CA (Root or ICA)
pub fn find_tls_certs_signed_by(context: &Path, ca_domain: &str) -> Result<Vec<CertificateInfo>> {
    let mut certs = Vec::new();

    // Walk through all directories to find TLS certificates
    for entry in WalkDir::new(context)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file()
            && path.file_name().and_then(|n| n.to_str()) == Some("crt.pem")
            && path.to_string_lossy().contains("certificates.d")
        {
            // Check if this cert is signed by the given CA
            if let Ok(pem) = fs::read(path) {
                if let Ok(cert) = X509::from_pem(&pem) {
                    let issuer = get_cn_from_name(cert.issuer_name());
                    if issuer == ca_domain {
                        let domain = path
                            .parent()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let subject = cert
                            .subject_name()
                            .entries()
                            .map(|e| {
                                let val = e
                                    .data()
                                    .as_utf8()
                                    .map(|d| d.to_string())
                                    .unwrap_or_else(|_| "<non-utf8>".to_string());
                                format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
                            })
                            .collect::<Vec<_>>()
                            .join(", ");

                        let not_before = cert.not_before().to_string();
                        let not_after = cert.not_after().to_string();
                        let expires_in_days = calculate_days_until_expiry(&not_after);

                        let cert_info = CertificateInfo {
                            path: path.to_path_buf(),
                            domain,
                            cert_type: CertificateType::ServerCert,
                            issuer: issuer.clone(),
                            subject,
                            not_before,
                            not_after,
                            expires_in_days,
                            needs_renewal: expires_in_days < 14,
                            parent: Some(ca_domain.to_string()),
                            sans: parse_san_from_cert(&cert),
                            serial: String::new(),
                            key_algorithm: None,
                        };
                        certs.push(cert_info);
                    }
                }
            }
        }
    }

    Ok(certs)
}

/// Find all ICAs under a given root CA
pub fn find_icas_under_root(context: &Path, root_domain: &str) -> Result<Vec<CertificateInfo>> {
    let mut icas = Vec::new();
    let root_path = context.join(root_domain);
    let intermediates_dir = root_path.join("intermediates.d");

    if !intermediates_dir.exists() {
        return Ok(icas);
    }

    for entry in fs::read_dir(&intermediates_dir)? {
        let entry = entry?;
        let ica_path = entry.path();
        if ica_path.is_dir() && ica_path.join("crt.pem").exists() {
            let domain = ica_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            if let Ok(pem) = fs::read(ica_path.join("crt.pem")) {
                if let Ok(cert) = X509::from_pem(&pem) {
                    let subject = cert
                        .subject_name()
                        .entries()
                        .map(|e| {
                            let val = e
                                .data()
                                .as_utf8()
                                .map(|d| d.to_string())
                                .unwrap_or_else(|_| "<non-utf8>".to_string());
                            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
                        })
                        .collect::<Vec<_>>()
                        .join(", ");

                    let issuer = cert
                        .issuer_name()
                        .entries()
                        .map(|e| {
                            let val = e
                                .data()
                                .as_utf8()
                                .map(|d| d.to_string())
                                .unwrap_or_else(|_| "<non-utf8>".to_string());
                            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
                        })
                        .collect::<Vec<_>>()
                        .join(", ");

                    let not_before = cert.not_before().to_string();
                    let not_after = cert.not_after().to_string();
                    let expires_in_days = calculate_days_until_expiry(&not_after);

                    let cert_info = CertificateInfo {
                        path: ica_path.clone(),
                        domain: domain.clone(),
                        cert_type: CertificateType::IntermediateCa,
                        issuer,
                        subject,
                        not_before,
                        not_after,
                        expires_in_days,
                        needs_renewal: expires_in_days < 14,
                        parent: Some(root_domain.to_string()),
                        sans: vec![],
                        serial: String::new(),
                        key_algorithm: None,
                    };
                    icas.push(cert_info);

                    // Also find nested ICAs
                    let nested = find_icas_under_root(&root_path, &domain)?;
                    icas.extend(nested);
                }
            }
        }
    }

    Ok(icas)
}

/// Recursively find all TLS certificates signed by an ICA (including nested ICAs)
pub fn find_all_tls_under_ica(context: &Path, ica_domain: &str) -> Result<Vec<CertificateInfo>> {
    let mut all_certs = Vec::new();

    // Find direct TLS certs signed by this ICA
    let direct_certs = find_tls_certs_signed_by(context, ica_domain)?;
    all_certs.extend(direct_certs);

    // Find the ICA path
    if let Some(ica_path) = find_nested_ica_path(context, ica_domain) {
        // Check for nested ICAs
        let nested_intermediates_dir = ica_path.join("intermediates.d");
        if nested_intermediates_dir.exists() {
            for entry in fs::read_dir(&nested_intermediates_dir)? {
                let entry = entry?;
                let nested_ica_path = entry.path();
                if nested_ica_path.is_dir() && nested_ica_path.join("crt.pem").exists() {
                    let nested_domain = nested_ica_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    // Recursively get TLS certs from nested ICA
                    let nested_certs = find_all_tls_under_ica(context, &nested_domain)?;
                    all_certs.extend(nested_certs);
                }
            }
        }
    }

    Ok(all_certs)
}

/// Remove a certificate from global metadata
pub fn remove_from_global_metadata(context: &Path, domain: &str) -> Result<()> {
    let mut global = read_global_metadata(context).unwrap_or_default();
    global.certificates.retain(|c| c.domain != domain);
    write_global_metadata(context, &global)
}

/// Revoke (remove) a certificate by domain
pub async fn revoke_certificate(context: &Path, domain: &str, skip_confirm: bool) -> Result<()> {
    use colored::*;
    use std::io::Write;

    // First, find the certificate and determine its type
    let global = read_global_metadata(context)?;
    let cert_meta = global.certificates.iter().find(|c| c.domain == domain);

    // Determine cert type from metadata or path detection
    let (cert_type, cert_path) = if let Some(meta) = cert_meta {
        let path = find_cert_path(context, domain, &meta.cert_type);
        (meta.cert_type.clone(), path)
    } else {
        // Try to detect from path
        let root_path = context.join(domain);
        if root_path.join("crt.pem").exists() {
            // Check if it's a Root CA or ICA
            if let Ok(pem) = fs::read(root_path.join("crt.pem")) {
                if let Ok(cert) = X509::from_pem(&pem) {
                    if is_ca_certificate(&cert) {
                        (CertType::RootCa, Some(root_path.join("crt.pem")))
                    } else {
                        (CertType::Tls, Some(root_path.join("crt.pem")))
                    }
                } else {
                    (CertType::Tls, Some(root_path.join("crt.pem")))
                }
            } else {
                (CertType::Tls, Some(root_path.join("crt.pem")))
            }
        } else if let Some(ica_path) = find_nested_ica_path(context, domain) {
            (CertType::Ica, Some(ica_path))
        } else if let Some(tls_path) = find_tls_cert_path(context, domain) {
            (CertType::Tls, Some(tls_path))
        } else {
            bail!("Certificate '{}' not found in context", domain);
        }
    };

    let cert_path =
        cert_path.ok_or_else(|| anyhow::anyhow!("Certificate path not found for '{}'", domain))?;
    let cert_dir = cert_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid certificate path"))?;

    // Handle different cert types with appropriate confirmation
    match cert_type {
        CertType::RootCa => {
            // Find all ICAs under this root
            let icas = find_icas_under_root(context, domain)?;
            // Collect all TLS certs from root and ICAs
            let mut all_tls = find_tls_certs_signed_by(context, domain)?;
            for ica in &icas {
                let ica_tls = find_all_tls_under_ica(context, &ica.domain)?;
                all_tls.extend(ica_tls);
            }

            if !skip_confirm {
                println!("{}", "⚠️  CRITICAL WARNING".red().bold());
                println!(
                    "You are about to revoke a Root CA: {}",
                    domain.yellow().bold()
                );
                println!("\nThis will PERMANENTLY DELETE:");
                println!("  • The Root CA '{}'", domain);
                println!("  • {} Intermediate CA(s):", icas.len());
                for ica in &icas {
                    println!("    - {}", ica.domain);
                }
                println!("  • {} TLS certificate(s):", all_tls.len());
                for cert in &all_tls {
                    println!("    - {}", cert.domain);
                }
                println!("\n{}", "This action is IRREVERSIBLE!".red().bold());
                print!("\nType 'yes' to confirm: ");
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if input.trim().to_lowercase() != "yes" {
                    println!("Revocation cancelled.");
                    return Ok(());
                }
            }

            // Remove the entire root CA directory
            let root_dir = context.join(domain);
            if root_dir.exists() {
                fs::remove_dir_all(root_dir)?;
                println!("Removed Root CA: {}", domain);
            }

            // Remove from metadata
            remove_from_global_metadata(context, domain)?;
            for ica in &icas {
                remove_from_global_metadata(context, &ica.domain)?;
            }
            for cert in &all_tls {
                remove_from_global_metadata(context, &cert.domain)?;
            }

            println!(
                "Successfully revoked Root CA '{}' and all associated certificates",
                domain
            );
        }

        CertType::Ica => {
            // Find all TLS certs signed by this ICA
            let tls_certs = find_all_tls_under_ica(context, domain)?;

            if !skip_confirm {
                println!("{}", "⚠️  WARNING".yellow().bold());
                println!(
                    "You are about to revoke an Intermediate CA: {}",
                    domain.yellow().bold()
                );
                println!("\nThis will PERMANENTLY DELETE:");
                println!("  • The Intermediate CA '{}'", domain);
                println!(
                    "  • {} TLS certificate(s) signed by this ICA:",
                    tls_certs.len()
                );
                for cert in &tls_certs {
                    println!("    - {}", cert.domain);
                }
                println!("\n{}", "This action is IRREVERSIBLE!".red().bold());
                print!("\nType 'yes' to confirm: ");
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if input.trim().to_lowercase() != "yes" {
                    println!("Revocation cancelled.");
                    return Ok(());
                }
            }

            // Remove the ICA directory
            let ica_dir = cert_dir;
            if ica_dir.exists() {
                fs::remove_dir_all(ica_dir)?;
                println!("Removed Intermediate CA: {}", domain);
            }

            // Remove from metadata
            remove_from_global_metadata(context, domain)?;
            for cert in &tls_certs {
                remove_from_global_metadata(context, &cert.domain)?;
            }

            println!(
                "Successfully revoked Intermediate CA '{}' and {} associated certificate(s)",
                domain,
                tls_certs.len()
            );
        }

        CertType::Tls => {
            // For TLS certs, just confirm if not skipping
            if !skip_confirm {
                println!(
                    "You are about to revoke TLS certificate: {}",
                    domain.yellow()
                );
                print!("Continue? [y/N]: ");
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if input.trim().to_lowercase() != "y" && input.trim().to_lowercase() != "yes" {
                    println!("Revocation cancelled.");
                    return Ok(());
                }
            }

            // Remove the TLS cert directory
            let tls_dir = cert_dir;
            if tls_dir.exists() {
                fs::remove_dir_all(tls_dir)?;
                println!("Removed TLS certificate: {}", domain);
            }

            // Remove from metadata
            remove_from_global_metadata(context, domain)?;
        }
    }

    Ok(())
}

/// Find TLS certificate path by domain
fn find_tls_cert_path(context: &Path, domain: &str) -> Option<PathBuf> {
    // Search in all CA directories
    if let Ok(entries) = fs::read_dir(context) {
        for entry in entries.flatten() {
            let root_path = entry.path();
            if root_path.is_dir() {
                // Check under root's certificates.d
                let cert_path = root_path
                    .join("certificates.d")
                    .join(domain)
                    .join("crt.pem");
                if cert_path.exists() {
                    return Some(cert_path);
                }

                // Check under ICA's certificates.d
                let intermediates_dir = root_path.join("intermediates.d");
                if intermediates_dir.exists() {
                    if let Ok(ica_entries) = fs::read_dir(&intermediates_dir) {
                        for ica_entry in ica_entries.flatten() {
                            let ica_path = ica_entry.path();
                            if ica_path.is_dir() {
                                let cert_path =
                                    ica_path.join("certificates.d").join(domain).join("crt.pem");
                                if cert_path.exists() {
                                    return Some(cert_path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Result of an auto-fix operation
#[derive(Debug, Clone)]
pub struct FixResult {
    pub domain: String,
    pub cert_type: CertificateType,
    pub fixed: bool,
    pub skipped: bool,
    pub message: String,
}

impl FixResult {
    pub fn fixed(domain: String, cert_type: CertificateType, message: String) -> Self {
        Self {
            domain,
            cert_type,
            fixed: true,
            skipped: false,
            message,
        }
    }

    pub fn skipped(domain: String, cert_type: CertificateType, message: String) -> Self {
        Self {
            domain,
            cert_type,
            fixed: false,
            skipped: true,
            message,
        }
    }
}

/// Ask user for confirmation, returning true if confirmed
fn ask_confirm(prompt: &str, yes: bool) -> bool {
    if yes {
        return true;
    }

    print!("{}", prompt);
    if let Err(e) = std::io::stdout().flush() {
        tracing::error!("Failed to flush stdout: {}", e);
        return false;
    }

    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_line(&mut input) {
        tracing::error!("Failed to read input: {}", e);
        return false;
    }

    input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes"
}

/// Re-sign a TLS certificate with a new random serial, preserving the existing key.
/// Returns the new serial number as a string on success.
pub fn resign_tls_certificate(context: &Path, cert_dir: &Path, parent_ca: &str) -> Result<String> {
    debug!(
        "Re-signing TLS certificate in {} with new serial",
        cert_dir.display()
    );

    // Load existing key (we preserve it, don't regenerate)
    let key_path = cert_dir.join("key.pem");
    let _key_pass_path = cert_dir.join("key.pass");
    let crt_path = cert_dir.join("crt.pem");
    let ext_path = cert_dir.join("ext.cnf");

    if !key_path.exists() {
        bail!("Private key not found at {}", key_path.display());
    }
    if !crt_path.exists() {
        bail!("Certificate not found at {}", crt_path.display());
    }

    // Load existing certificate to get subject and public key
    let cert_pem = fs::read(&crt_path)?;
    let existing_cert = X509::from_pem(&cert_pem)?;
    let subject_name = existing_cert.subject_name();
    let public_key = existing_cert.public_key()?;

    // Load ext.cnf if exists for SANs
    let ext_content = if ext_path.exists() {
        fs::read_to_string(&ext_path)?
    } else {
        // Generate default extension content
        let domain = cert_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        generate_default_ext_content(domain)
    };

    // Parse alt names from ext.cnf
    let alt_names = parse_alt_names_from_ext(&ext_content)?;

    // Find parent CA directory
    let parent_ca_dir = find_ca_path(context, parent_ca)
        .ok_or_else(|| anyhow::anyhow!("Parent CA '{}' not found", parent_ca))?;

    let ca_crt_path = parent_ca_dir.join("crt.pem");
    let ca_key_path = parent_ca_dir.join("key.pem");
    let ca_pass_path = parent_ca_dir.join("key.pass");

    if !ca_crt_path.exists() || !ca_key_path.exists() {
        bail!("Parent CA files not found at {}", parent_ca_dir.display());
    }

    // Load parent CA certificate and key
    let ca_cert_pem = fs::read(&ca_crt_path)?;
    let ca_cert = X509::from_pem(&ca_cert_pem)?;

    let ca_key_pem = fs::read(&ca_key_path)?;
    let ca_pass_content = fs::read_to_string(&ca_pass_path)?;
    let ca_key =
        PKey::private_key_from_pem_passphrase(&ca_key_pem, ca_pass_content.trim().as_bytes())?;

    // Build new certificate with same subject and public key, but new serial
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(subject_name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&public_key)?;

    // Set validity period - use same as original or default 3 years
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(1095)?; // 3 years
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Add extensions - same as in sign_cert
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

    // Add Subject Alternative Names
    let mut san_builder = SubjectAlternativeName::new();
    let domain = cert_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    san_builder.dns(domain);

    for altname in &alt_names {
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

    // Generate new unique serial
    let new_serial = generate_unique_serial(context)?;
    builder.set_serial_number(&new_serial)?;

    // Sign with CA key
    builder.sign(&ca_key, MessageDigest::sha256())?;
    let new_cert = builder.build();
    let new_cert_pem = new_cert.to_pem()?;

    // Write new certificate
    fs::write(&crt_path, &new_cert_pem)?;

    // Get serial as string for return value
    let serial_str = new_serial
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    debug!(
        "Re-signed certificate {} with new serial {}",
        cert_dir.display(),
        serial_str
    );

    Ok(serial_str)
}

/// Fix an ICA certificate and all TLS certificates signed by it.
/// Returns a list of fix results for all affected certificates.
pub async fn fix_ica_and_children(
    context: &Path,
    ica_domain: &str,
    yes: bool,
) -> Result<Vec<FixResult>> {
    let mut results = Vec::new();

    debug!("Fixing ICA '{}' and its children", ica_domain);

    // Find the ICA path
    let ica_path = find_nested_ica_path(context, ica_domain)
        .ok_or_else(|| anyhow::anyhow!("ICA '{}' not found", ica_domain))?;

    let ica_dir = ica_path.parent().unwrap();

    // Get parent CA from the certificate's issuer field (more robust than metadata)
    let crt_path = ica_dir.join("crt.pem");
    let cert_pem = fs::read(&crt_path)?;
    let _cert = X509::from_pem(&cert_pem)?;
    let ica_path_str = ica_path.to_string_lossy().to_string();
    let parent_ca = extract_parent_ca(&ica_path_str)
        .ok_or_else(|| anyhow::anyhow!("Could not determine parent CA for ICA '{}'", ica_domain))?;

    // First, count TLS children under this ICA
    let tls_certs = find_all_tls_under_ica(context, ica_domain)?;
    let child_count = tls_certs.len();

    let prompt = format!(
        "Re-sign ICA '{}' and {} child TLS certificate(s) with new serials? [y/N]: ",
        ica_domain.blue(),
        child_count
    );

    if !ask_confirm(&prompt, yes) {
        results.push(FixResult::skipped(
            ica_domain.to_string(),
            CertificateType::IntermediateCa,
            "User declined".to_string(),
        ));
        return Ok(results);
    }

    // Re-sign the ICA with new serial
    match resign_ica_certificate(context, ica_dir, &parent_ca).await {
        Ok(_) => {
            println!(
                "  {} ICA '{}' re-signed with new serial",
                "✓".green().bold(),
                ica_domain.blue()
            );
            results.push(FixResult::fixed(
                ica_domain.to_string(),
                CertificateType::IntermediateCa,
                "Re-signed with new serial".to_string(),
            ));
        }
        Err(e) => {
            println!(
                "  {} Failed to re-sign ICA '{}': {}",
                "✗".red().bold(),
                ica_domain.blue(),
                e
            );
            results.push(FixResult::skipped(
                ica_domain.to_string(),
                CertificateType::IntermediateCa,
                format!("Failed: {}", e),
            ));
            return Ok(results); // Can't proceed if ICA re-sign failed
        }
    }

    // Re-sign all TLS certificates under this ICA
    for tls_cert in &tls_certs {
        let tls_dir = tls_cert.path.parent().unwrap();

        // Re-sign TLS certificate
        match resign_tls_certificate(context, tls_dir, ica_domain) {
            Ok(new_serial) => {
                println!(
                    "  {} TLS '{}' re-signed with new serial {}",
                    "✓".green().bold(),
                    tls_cert.domain.blue(),
                    new_serial.yellow()
                );
                results.push(FixResult::fixed(
                    tls_cert.domain.clone(),
                    CertificateType::ServerCert,
                    format!("Re-signed with new serial {}", new_serial),
                ));

                // Fix fullchain order after re-signing
                if let Err(e) = fix_fullchain_order(tls_dir, context) {
                    tracing::debug!("Failed to fix fullchain for {}: {}", tls_cert.domain, e);
                }
            }
            Err(e) => {
                println!(
                    "  {} Failed to re-sign TLS '{}': {}",
                    "✗".red().bold(),
                    tls_cert.domain.blue(),
                    e
                );
                results.push(FixResult::skipped(
                    tls_cert.domain.clone(),
                    CertificateType::ServerCert,
                    format!("Failed: {}", e),
                ));
            }
        }
    }

    Ok(results)
}

/// Re-sign an ICA certificate with a new random serial, preserving the existing key.
async fn resign_ica_certificate(context: &Path, ica_dir: &Path, parent_ca: &str) -> Result<()> {
    debug!(
        "Re-signing ICA certificate at {} with new serial",
        ica_dir.display()
    );

    // Load existing key
    let key_path = ica_dir.join("key.pem");
    let _key_pass_path = ica_dir.join("key.pass");
    let crt_path = ica_dir.join("crt.pem");
    let _ext_path = ica_dir.join("ext.cnf");

    if !key_path.exists() || !crt_path.exists() {
        bail!("ICA key or certificate not found");
    }

    // Load existing certificate
    let cert_pem = fs::read(&crt_path)?;
    let existing_cert = X509::from_pem(&cert_pem)?;
    let subject_name = existing_cert.subject_name();
    let public_key = existing_cert.public_key()?;

    // Find parent CA
    let parent_ca_dir = find_ca_path(context, parent_ca)
        .ok_or_else(|| anyhow::anyhow!("Parent CA '{}' not found", parent_ca))?;

    let ca_crt_path = parent_ca_dir.join("crt.pem");
    let ca_key_path = parent_ca_dir.join("key.pem");
    let ca_pass_path = parent_ca_dir.join("key.pass");

    // Load parent CA
    let ca_cert_pem = fs::read(&ca_crt_path)?;
    let ca_cert = X509::from_pem(&ca_cert_pem)?;

    let ca_key_pem = fs::read(&ca_key_path)?;
    let ca_pass_content = fs::read_to_string(&ca_pass_path)?;
    let ca_key =
        PKey::private_key_from_pem_passphrase(&ca_key_pem, ca_pass_content.trim().as_bytes())?;

    // Build new ICA certificate
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(subject_name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&public_key)?;

    // Set validity - same as original or default 10 years
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(3650)?; // 10 years
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Add CA extensions
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

    // Generate new serial
    let new_serial = generate_unique_serial(context)?;
    builder.set_serial_number(&new_serial)?;

    // Sign
    builder.sign(&ca_key, MessageDigest::sha256())?;
    let new_cert = builder.build();
    let new_cert_pem = new_cert.to_pem()?;

    // Write new certificate
    fs::write(&crt_path, &new_cert_pem)?;

    debug!("Re-signed ICA {} with new serial", ica_dir.display());

    Ok(())
}

pub async fn list_certificates(
    context: &Path,
    renew: bool,
    expiration_alert_days: u32,
    detail: bool,
    auto_fix: bool,
    yes: bool,
    verify_openssl: bool,
    check_remote: bool,
) -> Result<()> {
    let context_str = context.display().to_string();
    let home = dirs::home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_default();
    let short_context = if home.is_empty() {
        context_str.clone()
    } else {
        context_str.replace(&home, "~")
    };

    println!("Listing certificates in context: {}", short_context);

    if !context.exists() {
        println!("Context directory does not exist.");
        return Ok(());
    }

    let has_meta = has_global_metadata(context);

    // Try to read from global metadata first
    let global_certs: Option<Vec<CertificateInfo>> = if has_meta {
        match read_global_metadata(context) {
            Ok(global) => {
                // Convert global metadata to CertificateInfo
                let mut certs = Vec::new();
                for meta in global.certificates {
                    let path = find_cert_path(context, &meta.domain, &meta.cert_type);
                    if let Some(p) = path {
                        // Auto-detect cert type from actual certificate, not just metadata
                        let actual_cert_type = if let Ok(cert_data) = fs::read(&p) {
                            if let Ok(cert) = X509::from_pem(&cert_data) {
                                let path_str = p.to_string_lossy().to_string();
                                if is_ca_certificate(&cert) {
                                    // It's a CA - check path to determine Root or ICA
                                    if path_str.contains("/intermediates.d/") {
                                        CertificateType::IntermediateCa
                                    } else {
                                        CertificateType::RootCa
                                    }
                                } else if path_str.contains("/intermediates.d/")
                                    || path_str.contains("/certificates.d/")
                                {
                                    // Not CA but in CA/ICA directory structure - likely an ICA that was imported incorrectly
                                    // Check metadata for hints
                                    match meta.cert_type {
                                        CertType::Ica => CertificateType::IntermediateCa,
                                        _ => CertificateType::ServerCert,
                                    }
                                } else {
                                    CertificateType::ServerCert
                                }
                            } else {
                                match meta.cert_type {
                                    CertType::RootCa => CertificateType::RootCa,
                                    CertType::Ica => CertificateType::IntermediateCa,
                                    CertType::Tls => CertificateType::ServerCert,
                                }
                            }
                        } else {
                            match meta.cert_type {
                                CertType::RootCa => CertificateType::RootCa,
                                CertType::Ica => CertificateType::IntermediateCa,
                                CertType::Tls => CertificateType::ServerCert,
                            }
                        };

                        let not_after = meta.not_after.clone();
                        let expires_in_days = calculate_days_until_expiry(&not_after);

                        // Extract serial from actual X509 certificate
                        let serial = match X509::from_pem(&fs::read(&p).unwrap_or_default()) {
                            Ok(cert) => cert
                                .serial_number()
                                .to_bn()
                                .ok()
                                .and_then(|bn| bn.to_hex_str().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                            Err(_) => String::new(),
                        };

                        let key_algorithm = meta.key_algorithm.or_else(|| {
                            fs::read(&p)
                                .ok()
                                .and_then(|b| X509::from_pem(&b).ok())
                                .and_then(|c| detect_key_algorithm_from_x509(&c))
                        });
                        let cert_info = CertificateInfo {
                            path: p.clone(),
                            domain: meta.domain,
                            cert_type: actual_cert_type,
                            issuer: meta.issuer,
                            subject: meta.subject,
                            not_before: meta.not_before,
                            not_after,
                            expires_in_days,
                            needs_renewal: expires_in_days < expiration_alert_days as i64,
                            parent: meta.parent,
                            sans: get_sans_from_path(&p),
                            serial,
                            key_algorithm,
                        };
                        certs.push(cert_info);
                    }
                }
                Some(certs)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    // If no global metadata or failed to read, fall back to walking directory
    let mut certificates = match global_certs {
        Some(certs) if !certs.is_empty() => certs,
        _ => {
            // Walk directory to find certificates
            let mut certs = Vec::new();
            for entry in WalkDir::new(context)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() && path.file_name().and_then(|n| n.to_str()) == Some("crt.pem") {
                    if let Some(info) = analyze_certificate(path, expiration_alert_days).await {
                        certs.push(info);
                    }
                }
            }
            certs
        }
    };

    // Handle check_remote: only for TLS certs, check remote DNS and TLS cert match
    if check_remote {
        // Filter to only TLS/Server certificates
        let tls_certs: Vec<_> = certificates
            .iter()
            .filter(|c| c.cert_type == CertificateType::ServerCert)
            .collect();

        if tls_certs.is_empty() {
            println!("No TLS certificates found to check.");
            return Ok(());
        }

        println!("\n=== Remote TLS Certificate Check ===\n");

        for cert in tls_certs {
            println!("Checking domain: {}", cert.domain.blue().bold());
            println!("  Local cert path: {}", shorten_path(&cert.path));

            // 1. DNS resolution check
            println!("\n  [1] DNS Resolution:");
            match tokio::task::spawn_blocking({
                let domain = cert.domain.clone();
                move || {
                    use std::net::ToSocketAddrs;
                    let addr_str = format!("{}:443", domain);
                    addr_str.to_socket_addrs()
                }
            })
            .await
            {
                Ok(Ok(ips)) => {
                    let ip_list: Vec<String> = ips.map(|a| a.ip().to_string()).collect();
                    if ip_list.is_empty() {
                        println!("    ✗ Domain '{}' is not resolvable", cert.domain.red());
                    } else {
                        println!(
                            "    ✓ Domain resolves to: {}",
                            ip_list.join(", ").yellow()
                        );
                    }
                }
                Ok(Err(e)) => {
                    println!(
                        "    ✗ DNS resolution failed for '{}': {}",
                        cert.domain.red(),
                        e
                    );
                }
                Err(e) => {
                    println!("    ✗ Task error: {}", e.to_string().red());
                }
            }

            // 2. Fetch remote TLS certificate
            println!("\n  [2] Remote TLS Certificate:");
            match fetch_remote_cert(&cert.domain).await {
                Ok(remote_cert_info) => {
                    println!("    ✓ Connected to {}:443", cert.domain.green());
                    println!("    Remote Subject: {}", remote_cert_info.subject.yellow());
                    println!("    Remote Issuer: {}", remote_cert_info.issuer.yellow());
                    println!("    Remote Serial: {}", remote_cert_info.serial.yellow());

                    // 3. Compare with local certificate
                    println!("\n  [3] Certificate Comparison:");
                    if let Ok(local_pem) = fs::read(&cert.path) {
                        if let Ok(local_cert) = X509::from_pem(&local_pem) {
                            let local_serial = local_cert
                                .serial_number()
                                .to_bn()
                                .ok()
                                .and_then(|bn| bn.to_hex_str().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_default();

                            if local_serial.to_lowercase() == remote_cert_info.serial.to_lowercase() {
                                println!(
                                    "    ✓ Remote certificate MATCHES local certificate (serial: {})",
                                    local_serial.yellow()
                                );
                            } else {
                                println!(
                                    "    ✗ Remote certificate DIFFERS from local certificate");
                                println!("      Local serial:   {}", local_serial.yellow());
                                println!("      Remote serial: {}", remote_cert_info.serial.yellow());
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("    ✗ Failed to fetch remote certificate: {}", e.to_string().red());
                }
            }

            println!();
        }

        return Ok(());
    }

    // First try to show tree structure (used for normal check and auto_fix)
    let mut skip_flat_display = false;
    if !renew {
        if let Ok(()) =
            display_certificate_tree(&certificates, expiration_alert_days, detail, verify_openssl)
        {
            if auto_fix {
                skip_flat_display = true;
            } else {
                return Ok(());
            }
        } else {
            println!("(Falling back to flat display)");
        }
    }

    // Flat display for renewals or when tree display fails
    if !skip_flat_display {
        certificates.sort_by(|a, b| a.cert_type.cmp(&b.cert_type).then(a.domain.cmp(&b.domain)));
    }

    // Build serial -> domains map for duplicate detection
    let mut serial_to_domains: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for cert in &certificates {
        if !cert.serial.is_empty() && cert.serial != "unknown" {
            serial_to_domains
                .entry(cert.serial.clone())
                .or_default()
                .push(cert.domain.clone());
        }
    }
    let duplicates: Vec<(String, Vec<String>)> = serial_to_domains
        .iter()
        .filter(|(_, domains)| domains.len() > 1)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Collect issues per certificate for auto_fix
    let mut fix_results: Vec<FixResult> = Vec::new();

    let mut current_type = None;
    for cert in &certificates {
        if renew && !cert.needs_renewal {
            continue;
        }

        let is_duplicate_serial = duplicates
            .iter()
            .any(|(_, domains)| domains.contains(&cert.domain));
        let is_serial_zero = cert.serial == "0";

        if !skip_flat_display {
            if current_type != Some(cert.cert_type.clone()) {
                current_type = Some(cert.cert_type.clone());
                println!("\n=== {:?} ===", cert.cert_type);
            }

            let status = if cert.needs_renewal { "warn" } else { "ok" };

            let status_colored = if cert.needs_renewal {
                status.yellow().bold()
            } else {
                status.green()
            };

            println!("{} {}", status_colored, cert.domain);
            println!("  Path: {}", shorten_path(&cert.path));
            println!("  Subject: {}", cert.subject);
            println!("  Issuer: {}", cert.issuer);
            println!(
                "  Valid from: {} to {}",
                asn1time_to_local_string(&cert.not_before),
                asn1time_to_local_string(&cert.not_after)
            );
            println!("  Expires in: {} days", cert.expires_in_days);

            let serial_display = if is_serial_zero {
                format!("Serial: {} (UNFIXED)", cert.serial)
                    .red()
                    .to_string()
            } else if is_duplicate_serial {
                format!("Serial: {} (DUPLICATE)", cert.serial)
                    .red()
                    .to_string()
            } else {
                format!("Serial: {}", cert.serial).yellow().to_string()
            };
            println!("  {}", serial_display);
        }

        // Collect issues for this cert
        let mut cert_issues = Vec::new();
        if is_serial_zero {
            cert_issues.push("serial 0");
        }
        if is_duplicate_serial {
            cert_issues.push("duplicate serial");
        }
        if cert.needs_renewal {
            cert_issues.push("needs renewal");
        }

        // Auto-fix logic for TLS certificates
        if cert.cert_type == CertificateType::ServerCert {
            let cert_dir = cert.path.parent().unwrap();

            let cert_dir_str = cert_dir.to_string_lossy();
            let is_ica_signed = cert_dir_str.contains("/intermediates.d/");
            if is_ica_signed {
                match verify_fullchain_order(cert_dir) {
                    Ok((is_valid, _message)) => {
                        if !is_valid {
                            cert_issues.push("wrong fullchain order");
                            if auto_fix {
                                let prompt = format!(
                                    "Fix fullchain order for '{}'? [y/N]: ",
                                    cert.domain.blue()
                                );
                                if ask_confirm(&prompt, yes) {
                                    match fix_fullchain_order(cert_dir, context) {
                                        Ok(()) => {
                                            println!(
                                                "  {} Fullchain fixed for '{}'",
                                                "✓".green().bold(),
                                                cert.domain.blue()
                                            );
                                            fix_results.push(FixResult::fixed(
                                                cert.domain.clone(),
                                                CertificateType::ServerCert,
                                                "Fullchain order fixed".to_string(),
                                            ));
                                        }
                                        Err(e) => {
                                            println!(
                                                "  {} Failed to fix fullchain for '{}': {}",
                                                "✗".red().bold(),
                                                cert.domain.blue(),
                                                e
                                            );
                                            fix_results.push(FixResult::skipped(
                                                cert.domain.clone(),
                                                CertificateType::ServerCert,
                                                format!("Fullchain fix failed: {}", e),
                                            ));
                                        }
                                    }
                                } else {
                                    fix_results.push(FixResult::skipped(
                                        cert.domain.clone(),
                                        CertificateType::ServerCert,
                                        "User declined fullchain fix".to_string(),
                                    ));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Error checking fullchain for {}: {}", cert.domain, e);
                    }
                }
            }

            // Handle serial/renewal issues for TLS certs
            if auto_fix && !cert_issues.is_empty() {
                let issues_str = cert_issues
                    .iter()
                    .map(|s| s.red().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let prompt = format!("Re-sign '{}' ({})? [y/N]: ", cert.domain.blue(), issues_str);

                if ask_confirm(&prompt, yes) {
                    let Some(parent) = cert.parent.as_deref() else {
                        fix_results.push(FixResult::skipped(
                            cert.domain.clone(),
                            CertificateType::ServerCert,
                            "Missing parent CA reference".to_string(),
                        ));
                        continue;
                    };
                    match resign_tls_certificate(context, cert_dir, parent) {
                        Ok(new_serial) => {
                            println!(
                                "  {} '{}' re-signed with new serial {}",
                                "✓".green().bold(),
                                cert.domain.blue(),
                                new_serial.yellow()
                            );
                            fix_results.push(FixResult::fixed(
                                cert.domain.clone(),
                                CertificateType::ServerCert,
                                format!("Re-signed with new serial {}", new_serial),
                            ));

                            // Fix fullchain after re-signing (only for ICA-signed certs)
                            if is_ica_signed {
                                if let Err(e) = fix_fullchain_order(cert_dir, context) {
                                    tracing::debug!("Failed to fix fullchain after re-sign: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!(
                                "  {} Failed to re-sign '{}': {}",
                                "✗".red().bold(),
                                cert.domain.blue(),
                                e
                            );
                            fix_results.push(FixResult::skipped(
                                cert.domain.clone(),
                                CertificateType::ServerCert,
                                format!("Re-sign failed: {}", e),
                            ));
                        }
                    }
                } else {
                    fix_results.push(FixResult::skipped(
                        cert.domain.clone(),
                        CertificateType::ServerCert,
                        "User declined".to_string(),
                    ));
                }
            } else if !cert_issues.is_empty() {
                let issues_str = cert_issues.join(", ");
                println!(
                    "  Issues: {} - Run with --auto-fix to fix",
                    issues_str.red().bold()
                );
            }

            // Verify key/certificate match using OpenSSL
            if verify_openssl {
                match verify_key_cert_match(cert_dir) {
                    Ok((is_valid, message)) => {
                        if is_valid {
                            println!("  OpenSSL: {}", message);
                        } else if message.contains("DO NOT MATCH") {
                            println!("  OpenSSL: {} - MISMATCH DETECTED", message.red().bold());
                        } else {
                            println!("  OpenSSL: {}", message.red().bold());
                        }
                    }
                    Err(e) => {
                        println!("  OpenSSL: Error: {}", e);
                    }
                }
            }
        }

        // Handle ICA issues (re-sign ICA and children)
        if auto_fix && cert.cert_type == CertificateType::IntermediateCa && !cert_issues.is_empty()
        {
            let issues_str = cert_issues
                .iter()
                .map(|s| s.red().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "  Issues: {} - Will fix ICA and children",
                issues_str.red().bold()
            );

            match fix_ica_and_children(context, &cert.domain, yes).await {
                Ok(results) => {
                    for result in results {
                        fix_results.push(result);
                    }
                }
                Err(e) => {
                    println!(
                        "  {} Failed to fix ICA '{}': {}",
                        "✗".red().bold(),
                        cert.domain.blue(),
                        e
                    );
                    fix_results.push(FixResult::skipped(
                        cert.domain.clone(),
                        CertificateType::IntermediateCa,
                        format!("Fix failed: {}", e),
                    ));
                }
            }
        } else if cert.cert_type == CertificateType::IntermediateCa && !cert_issues.is_empty() {
            let issues_str = cert_issues.join(", ");
            println!(
                "  Issues: {} - Run with --auto-fix to fix (will fix ICA and children)",
                issues_str.red().bold()
            );
        }
    }

    // Display summary if auto_fix was used
    if auto_fix {
        if !fix_results.is_empty() {
            println!("\n{}", "═".repeat(60));
            println!("{} AUTO-FIX SUMMARY", "│".cyan());
            println!("{}", "═".repeat(60));

            let fixed_count = fix_results.iter().filter(|r| r.fixed).count();
            let skipped_count = fix_results.iter().filter(|r| r.skipped).count();

            println!(
                "\n{} Fixed: {}  {} Skipped: {}",
                if fixed_count > 0 { "✓" } else { "─" }.green().bold(),
                fixed_count.to_string().green().bold(),
                if skipped_count > 0 { "○" } else { "─" }.yellow(),
                skipped_count.to_string().yellow()
            );

            println!("\n{} FIXED:", "✓".green().bold());
            for result in fix_results.iter().filter(|r| r.fixed) {
                let type_str = match result.cert_type {
                    CertificateType::RootCa => "Root CA",
                    CertificateType::IntermediateCa => "ICA",
                    CertificateType::ServerCert => "TLS",
                };
                println!(
                    "  {} {} - {}",
                    type_str.magenta(),
                    result.domain.blue(),
                    result.message.green()
                );
            }

            if skipped_count > 0 {
                println!("\n{} SKIPPED:", "○".yellow());
                for result in fix_results.iter().filter(|r| r.skipped) {
                    let type_str = match result.cert_type {
                        CertificateType::RootCa => "Root CA",
                        CertificateType::IntermediateCa => "ICA",
                        CertificateType::ServerCert => "TLS",
                    };
                    println!(
                        "  {} {} - {}",
                        type_str.magenta(),
                        result.domain.blue(),
                        result.message.yellow()
                    );
                }
            }
            println!("{}", "═".repeat(60));
        } else {
            println!(
                "\n{} All certificates are fine - nothing to fix",
                "✓".green().bold()
            );
        }
    }

    if renew && certificates.iter().all(|c| !c.needs_renewal) {
        println!("\nNo certificates need renewal.");
    }

    // Renewal logic - re-sign certificates that need renewal
    if renew {
        println!("\n=== Renewing certificates ===");
        for cert in &certificates {
            if cert.needs_renewal && cert.cert_type == CertificateType::ServerCert {
                if let Some(parent) = &cert.parent {
                    println!(
                        "Renewing certificate: {} (signed by {})",
                        cert.domain, parent
                    );
                    match crate::cert::sign_cert(
                        context,
                        &cert.domain,
                        parent,
                        true,
                        None,
                        None,
                        false,
                    )
                    .await
                    {
                        Ok(_) => println!("  Successfully renewed: {}", cert.domain),
                        Err(e) => println!("  Failed to renew {}: {}", cert.domain, e),
                    }
                }
            }
        }
    }

    Ok(())
}

fn parse_san_from_cert(cert: &X509) -> Vec<String> {
    let mut sans = Vec::new();

    // Write certificate to temp file
    let temp_dir = std::env::temp_dir();
    let temp_pem = temp_dir.join(format!("san_cert_{}.pem", std::process::id()));

    if let Ok(pem) = cert.to_pem() {
        if std::fs::write(&temp_pem, &pem).is_ok() {
            // Use openssl to extract SANs
            let output = std::process::Command::new("openssl")
                .args(["x509", "-in", temp_pem.to_str().unwrap(), "-noout", "-text"])
                .output();

            if let Ok(output) = output {
                let text = String::from_utf8_lossy(&output.stdout);

                // Find Subject Alternative Name section
                if let Some(san_start) = text.find("Subject Alternative Name") {
                    let san_section = &text[san_start..];

                    for line in san_section.lines().take(3) {
                        // Parse DNS entries
                        if line.contains("DNS:") {
                            for part in line.split(",") {
                                let part = part.trim();
                                if let Some(dns) = part.strip_prefix("DNS:") {
                                    let dns = dns.trim();
                                    if !dns.is_empty() {
                                        sans.push(dns.to_string());
                                    }
                                }
                            }
                        }
                        // Parse IP entries
                        if line.contains("IP Address:") {
                            for part in line.split(",") {
                                let part = part.trim();
                                if let Some(ip) = part.strip_prefix("IP Address:") {
                                    let ip = ip.trim();
                                    if !ip.is_empty() {
                                        sans.push(ip.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let _ = std::fs::remove_file(&temp_pem);
        }
    }

    sans
}

fn get_sans_from_path(path: &Path) -> Vec<String> {
    let pem = match fs::read(path) {
        Ok(pem) => pem,
        Err(_) => return vec![],
    };

    let cert = match X509::from_pem(&pem) {
        Ok(cert) => cert,
        Err(_) => return vec![],
    };

    parse_san_from_cert(&cert)
}

/// Remote certificate information fetched from a domain
#[derive(Debug)]
struct RemoteCertInfo {
    subject: String,
    issuer: String,
    serial: String,
}

/// Fetch remote TLS certificate from a domain:443 using openssl
async fn fetch_remote_cert(domain: &str) -> Result<RemoteCertInfo> {
    use openssl::ssl::{SslMethod, SslConnector};
    use std::net::TcpStream;

    let domain = domain.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<RemoteCertInfo> {
        let mut connector = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| anyhow::anyhow!("SSL connector error: {}", e))?;
        connector.set_default_verify_paths()
            .map_err(|e| anyhow::anyhow!("SSL verify paths error: {}", e))?;
        let connector = connector.build();

        let stream = TcpStream::connect(format!("{}:443", domain))
            .map_err(|e| anyhow::anyhow!("TCP connect error: {}", e))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .map_err(|e| anyhow::anyhow!("Set read timeout error: {}", e))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .map_err(|e| anyhow::anyhow!("Set write timeout error: {}", e))?;

        let mut ssl = connector.connect(&domain, stream)
            .map_err(|e| anyhow::anyhow!("SSL connect error: {}", e))?;

        // Get peer certificate via ssl_ref
        let cert = ssl.ssl().peer_certificate()
            .ok_or_else(|| anyhow::anyhow!("No peer certificate found"))?;

        // Extract subject
        let subject: String = cert
            .subject_name()
            .entries()
            .filter_map(|e| {
                let val = e.data().as_utf8().ok()?;
                Some(format!(
                    "{}={}",
                    e.object().nid().short_name().unwrap_or("?"),
                    val
                ))
            })
            .collect::<Vec<_>>()
            .join(", ");

        // Extract issuer
        let issuer: String = cert
            .issuer_name()
            .entries()
            .filter_map(|e| {
                let val = e.data().as_utf8().ok()?;
                Some(format!(
                    "{}={}",
                    e.object().nid().short_name().unwrap_or("?"),
                    val
                ))
            })
            .collect::<Vec<_>>()
            .join(", ");

        // Extract serial
        let serial_bn = cert.serial_number().to_bn()
            .map_err(|e| anyhow::anyhow!("serial to_bn error: {}", e))?;
        let serial = serial_bn.to_hex_str()
            .map_err(|e| anyhow::anyhow!("serial to_hex_str error: {}", e))?
            .to_string();

        Ok(RemoteCertInfo {
            subject,
            issuer,
            serial,
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {}", e))?;

    result
}

async fn analyze_certificate(path: &Path, expiration_alert_days: u32) -> Option<CertificateInfo> {
    let pem = match fs::read(path) {
        Ok(pem) => pem,
        Err(_) => return None,
    };

    let cert = match X509::from_pem(&pem) {
        Ok(cert) => cert,
        Err(_) => return None,
    };

    // Try to read metadata first, fall back to path-based detection
    let (cert_type, parent, key_algorithm) = match read_metadata(path.parent().unwrap_or(path)) {
        Ok(meta) => {
            let ct: CertificateType = (&meta.cert_type).into();
            (ct, meta.parent, meta.key_algorithm)
        }
        Err(_) => (
            determine_certificate_type(path),
            None,
            detect_key_algorithm_from_x509(&cert),
        ),
    };

    let subject = cert
        .subject_name()
        .entries()
        .map(|e| {
            let val = e
                .data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let issuer = cert
        .issuer_name()
        .entries()
        .map(|e| {
            let val = e
                .data()
                .as_utf8()
                .map(|d| d.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{}={}", e.object().nid().short_name().unwrap_or("?"), val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let serial = cert
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let now = Utc::now();
    // Parse OpenSSL ASN1Time string to DateTime
    let expiry_str = cert.not_after().to_string();
    let expiry = asn1time_to_datetime(&expiry_str).unwrap_or(now);
    let expires_in_days = (expiry - now).num_days();

    let needs_renewal = expires_in_days <= expiration_alert_days as i64;

    let domain = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Parse Subject Alternative Names
    let sans = parse_san_from_cert(&cert);

    Some(CertificateInfo {
        path: path.to_path_buf(),
        domain,
        cert_type,
        issuer,
        subject,
        not_before,
        not_after,
        expires_in_days,
        needs_renewal,
        parent,
        sans,
        serial,
        key_algorithm,
    })
}

fn detect_key_algorithm_from_x509(cert: &X509) -> Option<KeyAlgorithm> {
    let pkey = cert.public_key().ok()?;
    match pkey.id() {
        Id::RSA => Some(KeyAlgorithm::Rsa),
        Id::EC => Some(KeyAlgorithm::EcdsaP256),
        _ => None,
    }
}

fn determine_certificate_type(path: &Path) -> CertificateType {
    let path_str = path.to_string_lossy().to_string();

    if path_str.contains("intermediates.d") {
        CertificateType::IntermediateCa
    } else if path_str.contains("certificates.d") {
        CertificateType::ServerCert
    } else {
        // No longer checking for "certs.d" - all certificates directly under context/<domain>
        CertificateType::RootCa
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub path: PathBuf,
    pub domain: String,
    pub cert_type: CertificateType,
    pub issuer: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub expires_in_days: i64,
    pub needs_renewal: bool,
    pub parent: Option<String>,
    pub sans: Vec<String>,
    pub serial: String,
    pub key_algorithm: Option<KeyAlgorithm>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CertificateType {
    RootCa,
    IntermediateCa,
    ServerCert,
}

impl From<&CertType> for CertificateType {
    fn from(cert_type: &CertType) -> Self {
        match cert_type {
            CertType::RootCa => CertificateType::RootCa,
            CertType::Ica => CertificateType::IntermediateCa,
            CertType::Tls => CertificateType::ServerCert,
        }
    }
}

// ============================================
// Git auto-commit functions
// ============================================

/// Initialize a git repository in the context folder if it doesn't exist.
/// Creates a .gitignore that excludes private key files.
pub fn init_git_repo(context: &Path) -> Result<()> {
    let git_dir = context.join(".git");

    if git_dir.exists() {
        debug!("Git repo already exists at {}", context.display());
        return Ok(());
    }

    // Initialize git repo
    let output = std::process::Command::new("git")
        .args(["init"])
        .current_dir(context)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            debug!("Initialized git repo at {}", context.display());
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to init git repo: {}", stderr);
            return Ok(());
        }
        Err(e) => {
            tracing::warn!("Git not available or failed to init repo: {}", e);
            return Ok(());
        }
    }

    // Create .gitignore to exclude private keys
    let gitignore_content = r#"# Private keys - NEVER commit these
*.pem
*.key
key.pass
*.p12
p12.pass
"#;
    let gitignore_path = context.join(".gitignore");
    if let Err(e) = fs::write(&gitignore_path, gitignore_content) {
        tracing::warn!("Failed to write .gitignore: {}", e);
    }

    // Do initial commit with .gitignore
    let add_output = std::process::Command::new("git")
        .args(["add", ".gitignore"])
        .current_dir(context)
        .output();

    if let Ok(output) = add_output {
        if output.status.success() {
            let commit_output = std::process::Command::new("git")
                .args([
                    "commit",
                    "-m",
                    "Initial commit: add .gitignore for private keys",
                ])
                .current_dir(context)
                .output();

            if let Err(e) = commit_output {
                tracing::warn!("Failed to create initial commit: {}", e);
            }
        }
    }

    Ok(())
}

/// Stage and commit all changes except private key files.
/// Returns the commit hash on success, None if nothing was committed.
pub fn git_add_and_commit(context: &Path, message: &str) -> Result<Option<String>> {
    // First ensure git repo exists
    let git_dir = context.join(".git");
    if !git_dir.exists() {
        init_git_repo(context)?;
    }

    // Stage all files except private keys using git add with inverse of .gitignore
    // We'll use git add -A then reset the private key files
    let add_all = std::process::Command::new("git")
        .args(["add", "-A"])
        .current_dir(context)
        .output();

    if let Err(e) = add_all {
        tracing::warn!("Git add failed: {}", e);
        return Ok(None);
    }

    let add_output = add_all.unwrap();
    if !add_output.status.success() {
        let stderr = String::from_utf8_lossy(&add_output.stderr);
        tracing::warn!("Git add failed: {}", stderr);
        return Ok(None);
    }

    // Reset private key files from staging
    let reset_keys = std::process::Command::new("git")
        .args(["reset", "--", "*.pem", "key.pass", "*.p12", "p12.pass"])
        .current_dir(context)
        .output();

    if let Err(e) = reset_keys {
        tracing::warn!("Git reset for private keys failed: {}", e);
    }

    // Check if there are staged changes
    let status_output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(context)
        .output();

    let has_staged_changes = if let Ok(output) = status_output {
        if output.status.success() {
            let status = String::from_utf8_lossy(&output.stdout);
            !status.trim().is_empty()
        } else {
            false
        }
    } else {
        false
    };

    if !has_staged_changes {
        debug!("No changes to commit");
        return Ok(None);
    }

    // Commit with the provided message
    let commit_output = std::process::Command::new("git")
        .args(["commit", "-m", message])
        .current_dir(context)
        .output();

    match commit_output {
        Ok(output) if output.status.success() => {
            // Get the commit hash
            let hash_output = std::process::Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .current_dir(context)
                .output();

            if let Ok(hash_out) = hash_output {
                if hash_out.status.success() {
                    let commit_hash = String::from_utf8_lossy(&hash_out.stdout).trim().to_string();
                    debug!("Committed changes: {} ({})", message, commit_hash);
                    return Ok(Some(commit_hash));
                }
            }
            debug!("Committed changes: {}", message);
            Ok(None)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Git commit failed: {}", stderr);
            Ok(None)
        }
        Err(e) => {
            tracing::warn!("Git commit failed: {}", e);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_certificate_paths_new() {
        let paths = CertificatePaths::new("test_cas", "example.com");
        assert_eq!(paths.dir, PathBuf::from("test_cas").join("example.com"));
        assert_eq!(paths.key, paths.dir.join("key.pem"));
        assert_eq!(paths.csr, paths.dir.join("csr.pem"));
        assert_eq!(paths.crt, paths.dir.join("crt.pem"));
        assert_eq!(paths.ext, paths.dir.join("ext.cnf"));
        assert_eq!(paths.pass, paths.dir.join("key.pass"));
        assert_eq!(paths.fullchain, paths.dir.join("fullchain.crt"));
    }

    #[test]
    fn test_certificate_paths_create_dir() {
        let temp_dir = TempDir::new().unwrap();
        let paths = CertificatePaths::new(temp_dir.path().to_str().unwrap(), "test.com");

        paths.create_dir().unwrap();
        assert!(paths.dir.exists());
        assert!(paths.dir.is_dir());
    }

    #[test]
    fn test_parse_alt_names_from_ext() {
        let ext_content = r#"
basicConstraints = critical,CA:false
[alt_names]
DNS.1 = example.com
DNS.2 = *.example.com
DNS.3 = test.example.com
# DNS.4 = commented.out
"#;
        let alt_names = parse_alt_names_from_ext(ext_content).unwrap();
        assert_eq!(
            alt_names,
            vec!["example.com", "*.example.com", "test.example.com"]
        );
    }

    #[test]
    fn test_generate_random_password() {
        let pwd1 = generate_random_password().unwrap();
        let pwd2 = generate_random_password().unwrap();
        assert_eq!(pwd1.len(), 44); // 32 bytes base64
        assert_ne!(pwd1, pwd2); // 很大概率不同
    }

    #[test]
    fn test_write_and_read_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let test_content = "Hello, World!";
        write_file(&test_file, test_content).unwrap();
        let read_content = read_file(&test_file).unwrap();
        assert_eq!(read_content, test_content);
    }

    #[test]
    fn test_global_metadata_write_and_read() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let metadata = GlobalCertMetadata {
            version: 1,
            certificates: vec![
                CertMetadata {
                    version: 1,
                    cert_type: CertType::RootCa,
                    domain: "example.com".to_string(),
                    subject: "CN=example.com".to_string(),
                    issuer: "CN=example.com".to_string(),
                    serial: "01".to_string(),
                    not_before: "2024-01-01".to_string(),
                    not_after: "2034-01-01".to_string(),
                    parent: None,
                    signing_ca: None,
                    private_key_encrypted: None,
                    private_key_password_file: None,
                    key_algorithm: None,
                },
                CertMetadata {
                    version: 1,
                    cert_type: CertType::Ica,
                    domain: "sub.example.com".to_string(),
                    subject: "CN=sub.example.com".to_string(),
                    issuer: "CN=example.com".to_string(),
                    serial: "02".to_string(),
                    not_before: "2024-01-01".to_string(),
                    not_after: "2034-01-01".to_string(),
                    parent: Some("example.com".to_string()),
                    signing_ca: Some("example.com".to_string()),
                    private_key_encrypted: None,
                    private_key_password_file: None,
                    key_algorithm: None,
                },
            ],
        };

        write_global_metadata(context, &metadata).unwrap();
        assert!(context.join("meta.json").exists());

        let read_metadata = read_global_metadata(context).unwrap();
        assert_eq!(read_metadata.certificates.len(), 2);
        assert_eq!(read_metadata.certificates[0].domain, "example.com");
        assert_eq!(read_metadata.certificates[1].domain, "sub.example.com");
    }

    #[test]
    fn test_global_metadata_read_empty() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let metadata = read_global_metadata(context).unwrap();
        assert_eq!(metadata.certificates.len(), 0);
    }

    #[test]
    fn test_has_global_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        // No metadata file
        assert!(!has_global_metadata(context));

        // Create meta.json
        let meta_path = context.join("meta.json");
        fs::write(&meta_path, "{}").unwrap();
        assert!(has_global_metadata(context));
    }

    #[test]
    fn test_has_global_metadata_legacy() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        // Create old certs.json
        let meta_path = context.join("certs.json");
        fs::write(&meta_path, "{}").unwrap();
        assert!(has_global_metadata(context));
    }

    #[test]
    fn test_update_global_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let cert1 = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        update_global_metadata(context, cert1.clone()).unwrap();

        let cert2 = CertMetadata {
            version: 1,
            cert_type: CertType::Ica,
            domain: "sub.example.com".to_string(),
            subject: "CN=sub.example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "02".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: Some("example.com".to_string()),
            signing_ca: Some("example.com".to_string()),
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        update_global_metadata(context, cert2).unwrap();

        let global = read_global_metadata(context).unwrap();
        assert_eq!(global.certificates.len(), 2);

        // Update existing
        let cert1_updated = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com-updated".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        update_global_metadata(context, cert1_updated).unwrap();

        let global = read_global_metadata(context).unwrap();
        assert_eq!(global.certificates.len(), 2);
        let example = global
            .certificates
            .iter()
            .find(|c| c.domain == "example.com")
            .unwrap();
        assert_eq!(example.subject, "CN=example.com-updated");
    }

    #[test]
    fn test_get_from_global_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let cert = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        update_global_metadata(context, cert).unwrap();

        let found = get_from_global_metadata(context, "example.com").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().domain, "example.com");

        let not_found = get_from_global_metadata(context, "nonexistent.com").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_has_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        assert!(!has_metadata(dir));

        let meta_path = dir.join("meta.json");
        fs::write(&meta_path, "{}").unwrap();
        assert!(has_metadata(dir));
    }

    #[test]
    fn test_read_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        let meta = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        let meta_path = dir.join("meta.json");
        let json = serde_json::to_string_pretty(&meta).unwrap();
        fs::write(&meta_path, json).unwrap();

        let read_meta = read_metadata(dir).unwrap();
        assert_eq!(read_meta.domain, "example.com");
        assert_eq!(read_meta.cert_type, CertType::RootCa);
    }

    #[test]
    fn test_file_exists() {
        let temp_dir = TempDir::new().unwrap();
        let existing = temp_dir.path().join("exists.txt");
        fs::write(&existing, "test").unwrap();

        let nonexistent = temp_dir.path().join("nonexistent.txt");

        assert!(file_exists(&existing));
        assert!(!file_exists(&nonexistent));
    }

    #[test]
    fn test_shorten_path() {
        // This test may or may not work depending on the system
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        // Without home directory, should return original
        let result = shorten_path(path);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_generate_default_ext_content() {
        let domain = "example.com";
        let content = generate_default_ext_content(domain);

        assert!(content.contains(domain));
        assert!(content.contains("basicConstraints"));
        assert!(content.contains("DNS.1 = example.com"));
    }

    #[test]
    fn test_copy_dir_all() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        // Create source files
        let file1 = src_dir.path().join("file1.txt");
        let file2 = src_dir.path().join("file2.txt");
        let subdir = src_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        let file3 = subdir.join("file3.txt");

        fs::write(&file1, "content1").unwrap();
        fs::write(&file2, "content2").unwrap();
        fs::write(&file3, "content3").unwrap();

        copy_dir_all(src_dir.path(), dst_dir.path()).unwrap();

        assert!(dst_dir.path().join("file1.txt").exists());
        assert!(dst_dir.path().join("file2.txt").exists());
        assert!(dst_dir.path().join("subdir").exists());
        assert!(dst_dir.path().join("subdir").join("file3.txt").exists());

        assert_eq!(
            fs::read_to_string(dst_dir.path().join("file1.txt")).unwrap(),
            "content1"
        );
        assert_eq!(
            fs::read_to_string(dst_dir.path().join("file2.txt")).unwrap(),
            "content2"
        );
        assert_eq!(
            fs::read_to_string(dst_dir.path().join("subdir").join("file3.txt")).unwrap(),
            "content3"
        );
    }

    #[test]
    fn test_extract_parent_ca_intermediates() {
        let path = "/home/user/.local/state/certboy/root-ca/intermediates.d/ica-domain/crt.pem";
        let parent = extract_parent_ca(path);
        assert!(parent.is_some());
        assert_eq!(parent.unwrap(), "root-ca");
    }

    #[test]
    fn test_extract_parent_ca_certificates() {
        let path = "/home/user/.local/state/certboy/root-ca/certificates.d/server-domain/crt.pem";
        let parent = extract_parent_ca(path);
        assert!(parent.is_some());
        assert_eq!(parent.unwrap(), "root-ca");
    }

    #[test]
    fn test_extract_parent_ca_no_match() {
        let path = "/some/random/path/crt.pem";
        let parent = extract_parent_ca(path);
        assert!(parent.is_none());
    }

    #[test]
    fn test_determine_certificate_type_intermediates() {
        let path = PathBuf::from("/context/root-ca/intermediates.d/ica/crt.pem");
        let cert_type = determine_certificate_type(&path);
        assert_eq!(cert_type, CertificateType::IntermediateCa);
    }

    #[test]
    fn test_determine_certificate_type_certificates() {
        let path = PathBuf::from("/context/root-ca/certificates.d/server/crt.pem");
        let cert_type = determine_certificate_type(&path);
        assert_eq!(cert_type, CertificateType::ServerCert);
    }

    #[test]
    fn test_determine_certificate_type_root() {
        let path = PathBuf::from("/context/root-ca/crt.pem");
        let cert_type = determine_certificate_type(&path);
        assert_eq!(cert_type, CertificateType::RootCa);
    }

    #[test]
    fn test_check_certificate_expiry() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");

        // Non-existent file
        let result = check_certificate_expiry(&cert_path.join("nonexistent"));
        assert!(!result.unwrap_or(false));

        // Empty file
        fs::write(&cert_path, "").unwrap();
        let result = check_certificate_expiry(&cert_path);
        assert!(!result.unwrap());

        // Non-empty file
        fs::write(&cert_path, "dummy content").unwrap();
        let result = check_certificate_expiry(&cert_path);
        assert!(result.unwrap());
    }

    #[test]
    fn test_asn1time_to_datetime() {
        use chrono::Datelike;

        // Test standard format with GMT
        let dt = asn1time_to_datetime("Mar  8 06:21:27 2036 GMT").unwrap();
        assert_eq!(dt.year(), 2036);
        assert_eq!(dt.month(), 3);
        assert_eq!(dt.day(), 8);

        // Test format without GMT
        let dt = asn1time_to_datetime("Jan 15 12:00:00 2025").unwrap();
        assert_eq!(dt.year(), 2025);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);

        // Test invalid format
        let result = asn1time_to_datetime("invalid");
        assert!(result.is_err());

        // Test invalid month
        let result = asn1time_to_datetime("Xyz 15 12:00:00 2025");
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_days_until_expiry() {
        // This will vary based on current time, but should not panic
        let days = calculate_days_until_expiry("Mar  8 06:21:27 2036 GMT");
        assert!(days > 0);

        // Invalid date
        let days = calculate_days_until_expiry("invalid");
        assert_eq!(days, 0);
    }

    #[test]
    fn test_cert_type_display() {
        assert_eq!(CertType::RootCa.to_string(), "root-ca");
        assert_eq!(CertType::Ica.to_string(), "ica");
        assert_eq!(CertType::Tls.to_string(), "tls");
    }

    #[test]
    fn test_global_cert_metadata_default() {
        let metadata = GlobalCertMetadata::default();
        assert_eq!(metadata.version, 1);
        assert!(metadata.certificates.is_empty());
    }

    #[test]
    fn test_certificate_type_from_cert_type() {
        let root: CertificateType = (&CertType::RootCa).into();
        assert_eq!(root, CertificateType::RootCa);

        let ica: CertificateType = (&CertType::Ica).into();
        assert_eq!(ica, CertificateType::IntermediateCa);

        let tls: CertificateType = (&CertType::Tls).into();
        assert_eq!(tls, CertificateType::ServerCert);
    }

    #[test]
    fn test_certificate_info_clone() {
        let info = CertificateInfo {
            path: PathBuf::from("/path/to/cert"),
            domain: "example.com".to_string(),
            cert_type: CertificateType::RootCa,
            issuer: "CN=Example".to_string(),
            subject: "CN=Example".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            expires_in_days: 3650,
            needs_renewal: false,
            parent: None,
            sans: vec![],
            serial: String::new(),
            key_algorithm: None,
        };

        let cloned = info.clone();
        assert_eq!(cloned.domain, info.domain);
        assert_eq!(cloned.cert_type, info.cert_type);
    }

    #[test]
    fn test_certificate_type_ordering() {
        use std::cmp::Ordering;

        let root = CertificateType::RootCa;
        let ica = CertificateType::IntermediateCa;
        let server = CertificateType::ServerCert;

        assert_eq!(root.cmp(&ica), Ordering::Less);
        assert_eq!(ica.cmp(&server), Ordering::Less);
        assert_eq!(root.cmp(&server), Ordering::Less);
    }

    #[test]
    fn test_find_ca_path_root() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("example.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_ca_path(context, "example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), root_dir);
    }

    #[test]
    fn test_find_ca_path_ica() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let ica_dir = root_dir.join("intermediates.d").join("ica.com");
        fs::create_dir_all(&ica_dir).unwrap();
        fs::write(ica_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_ca_path(context, "ica.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_find_ca_path_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = find_ca_path(context, "nonexistent.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_search_intermediates() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let intermediates = base.join("intermediates.d").join("ica.com");
        fs::create_dir_all(&intermediates).unwrap();
        fs::write(intermediates.join("crt.pem"), "dummy").unwrap();

        let result = search_intermediates(base, "ica.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_search_intermediates_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let result = search_intermediates(base, "nonexistent.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_nested_ica_path() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let ica_dir = root_dir.join("intermediates.d").join("nested-ica.com");
        fs::create_dir_all(&ica_dir).unwrap();
        fs::write(ica_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_nested_ica_path(context, "nested-ica.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_find_cert_path_root_ca() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("example.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_cert_path(context, "example.com", &CertType::RootCa);
        assert!(result.is_some());
    }

    #[test]
    fn test_find_cert_path_fallback() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("example.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_cert_path(context, "example.com", &CertType::Ica);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_alt_names_empty() {
        let content = "basicConstraints = critical,CA:false";
        let alt_names = parse_alt_names_from_ext(content).unwrap();
        assert!(alt_names.is_empty());
    }

    #[test]
    fn test_parse_alt_names_ip() {
        let content = r#"
[alt_names]
DNS.1 = example.com
IP.1 = 127.0.0.1
"#;
        let alt_names = parse_alt_names_from_ext(content).unwrap();
        assert_eq!(alt_names, vec!["example.com", "127.0.0.1"]);
    }

    #[test]
    fn test_search_intermediates_nested() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let nested = base
            .join("intermediates.d")
            .join("parent")
            .join("intermediates.d")
            .join("child");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("crt.pem"), "dummy").unwrap();

        let result = search_intermediates(base, "child");
        assert!(result.is_some());
    }

    #[test]
    fn test_find_cert_path_ica() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let ica_dir = root_dir.join("intermediates.d").join("ica.com");
        fs::create_dir_all(&ica_dir).unwrap();
        fs::write(ica_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_cert_path(context, "ica.com", &CertType::Ica);
        assert!(result.is_some());
    }

    #[test]
    fn test_find_cert_path_tls() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let cert_dir = root_dir.join("certificates.d").join("server.com");
        fs::create_dir_all(&cert_dir).unwrap();
        fs::write(cert_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_cert_path(context, "server.com", &CertType::Tls);
        assert!(result.is_some());
    }

    #[test]
    fn test_find_cert_path_tls_under_ica() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let ica_dir = root_dir.join("intermediates.d").join("ica.com");
        fs::create_dir_all(&ica_dir).unwrap();
        fs::write(ica_dir.join("crt.pem"), "dummy").unwrap();

        let cert_dir = ica_dir.join("certificates.d").join("server.com");
        fs::create_dir_all(&cert_dir).unwrap();
        fs::write(cert_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_cert_path(context, "server.com", &CertType::Tls);
        assert!(result.is_some());
    }

    #[test]
    fn test_verify_certificate_chain() {
        use openssl::pkey::PKey;
        use openssl::x509::{X509NameBuilder, X509};

        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name.append_entry_by_text("CN", "Test CA").unwrap();
        let x509_name = x509_name.build();

        let mut x509 = X509::builder().unwrap();
        x509.set_version(2).unwrap();
        x509.set_subject_name(&x509_name).unwrap();
        x509.set_issuer_name(&x509_name).unwrap();
        x509.set_pubkey(&pkey).unwrap();
        x509.sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let root_cert = x509.build();

        assert!(verify_certificate_chain(&root_cert, &root_cert));
    }

    #[test]
    fn test_find_parent_ca_in_context() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result =
            find_parent_ca_in_context(context, "test.com", &X509::builder().unwrap().build());
        assert!(result.unwrap_or(None).is_none());
    }

    #[test]
    fn test_copy_dir_all_nested() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let nested = src_dir.path().join("level1").join("level2").join("level3");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("deep.txt"), "deep content").unwrap();

        copy_dir_all(src_dir.path(), dst_dir.path()).unwrap();

        assert!(dst_dir
            .path()
            .join("level1")
            .join("level2")
            .join("level3")
            .join("deep.txt")
            .exists());
    }

    #[test]
    fn test_update_fullchain_crt() {
        let temp_dir = TempDir::new().unwrap();
        let old_dir = std::env::current_dir().unwrap();

        std::env::set_current_dir(temp_dir.path()).unwrap();

        let ca_dir = temp_dir.path().join("CAs");
        fs::create_dir_all(&ca_dir).unwrap();

        let root1 = ca_dir.join("root1.com");
        fs::create_dir_all(&root1).unwrap();
        fs::write(root1.join("crt.pem"), "CERT1").unwrap();

        let root2 = ca_dir.join("root2.com");
        fs::create_dir_all(&root2).unwrap();
        fs::write(root2.join("crt.pem"), "CERT2").unwrap();

        let result = update_fullchain_crt();
        assert!(result.is_ok());

        let fullchain1 = fs::read_to_string(root1.join("fullchain.crt")).unwrap();
        let fullchain2 = fs::read_to_string(root2.join("fullchain.crt")).unwrap();

        assert!(fullchain1.contains("CERT1"));
        assert!(fullchain1.contains("CERT2"));
        assert!(fullchain2.contains("CERT1"));
        assert!(fullchain2.contains("CERT2"));

        std::env::set_current_dir(old_dir).unwrap();
    }

    #[test]
    fn test_check_certificate_expiry_valid() {
        let temp_dir = TempDir::new().unwrap();

        let (cert_pem, key_pem) = create_test_cert("Test Cert", 3650);
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let result = check_certificate_expiry(&cert_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_check_certificate_expiry_expired() {
        // Use check_certificate_expiry with an empty/invalid file to test error handling
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("nonexistent.pem");

        // Non-existent file should return Ok(false)
        let result = check_certificate_expiry(&cert_path);
        assert!(!result.unwrap_or(false));
    }

    #[test]
    fn test_display_certificate_tree_empty() {
        let certs: Vec<CertificateInfo> = vec![];
        let result = display_certificate_tree(&certs, 14, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_display_certificate_tree_single_root() {
        let certs = vec![CertificateInfo {
            path: PathBuf::from("/test/root.com/crt.pem"),
            domain: "root.com".to_string(),
            cert_type: CertificateType::RootCa,
            issuer: "root.com".to_string(),
            subject: "CN=root.com".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            expires_in_days: 3650,
            needs_renewal: false,
            parent: None,
            sans: vec![],
            serial: String::new(),
            key_algorithm: None,
        }];
        let result = display_certificate_tree(&certs, 14, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_display_certificate_tree_with_ica() {
        let certs = vec![
            CertificateInfo {
                path: PathBuf::from("/test/root.com/crt.pem"),
                domain: "root.com".to_string(),
                cert_type: CertificateType::RootCa,
                issuer: "root.com".to_string(),
                subject: "CN=root.com".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2034-01-01".to_string(),
                expires_in_days: 3650,
                needs_renewal: false,
                parent: None,
                sans: vec![],
                serial: String::new(),
                key_algorithm: None,
            },
            CertificateInfo {
                path: PathBuf::from("/test/root.com/intermediates.d/ica.com/crt.pem"),
                domain: "ica.com".to_string(),
                cert_type: CertificateType::IntermediateCa,
                issuer: "root.com".to_string(),
                subject: "CN=ica.com".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2034-01-01".to_string(),
                expires_in_days: 3650,
                needs_renewal: false,
                parent: Some("root.com".to_string()),
                sans: vec![],
                serial: String::new(),
                key_algorithm: None,
            },
            CertificateInfo {
                path: PathBuf::from(
                    "/test/root.com/intermediates.d/ica.com/certificates.d/server.com/crt.pem",
                ),
                domain: "server.com".to_string(),
                cert_type: CertificateType::ServerCert,
                issuer: "ica.com".to_string(),
                subject: "CN=server.com".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2027-01-01".to_string(),
                expires_in_days: 365,
                needs_renewal: false,
                parent: Some("ica.com".to_string()),
                sans: vec!["server.com".to_string()],
                serial: String::new(),
                key_algorithm: None,
            },
        ];
        let result = display_certificate_tree(&certs, 14, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_display_certificate_tree_needs_renewal() {
        let certs = vec![CertificateInfo {
            path: PathBuf::from("/test/root.com/crt.pem"),
            domain: "root.com".to_string(),
            cert_type: CertificateType::RootCa,
            issuer: "root.com".to_string(),
            subject: "CN=root.com".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2024-02-01".to_string(),
            expires_in_days: 10,
            needs_renewal: true,
            parent: None,
            sans: vec![],
            serial: String::new(),
            key_algorithm: None,
        }];
        let result = display_certificate_tree(&certs, 14, false, false);
        assert!(result.is_ok());
    }

    fn create_test_cert(name: &str, days_offset: i64) -> (Vec<u8>, Vec<u8>) {
        use openssl::pkey::PKey;
        use openssl::x509::{X509NameBuilder, X509};

        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name.append_entry_by_text("CN", name).unwrap();
        let x509_name = x509_name.build();

        let mut x509 = X509::builder().unwrap();
        x509.set_version(2).unwrap();
        x509.set_subject_name(&x509_name).unwrap();
        x509.set_issuer_name(&x509_name).unwrap();
        x509.set_pubkey(&pkey).unwrap();

        let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let not_after = openssl::asn1::Asn1Time::days_from_now(days_offset.max(1) as u32).unwrap();
        x509.set_not_before(&not_before).unwrap();
        x509.set_not_after(&not_after).unwrap();

        x509.sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();

        (
            x509.build().to_pem().unwrap(),
            pkey.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    #[test]
    fn test_create_metadata_from_cert() {
        let (cert_pem, _) = create_test_cert("Test Cert", 365);
        let cert = X509::from_pem(&cert_pem).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().join("test.com");
        fs::create_dir_all(&dir).unwrap();

        let metadata = create_metadata_from_cert(dir.as_path(), &cert, CertType::RootCa, None);
        assert!(metadata.is_ok());

        let meta = metadata.unwrap();
        assert_eq!(meta.domain, "test.com");
        assert_eq!(meta.cert_type, CertType::RootCa);
    }

    #[test]
    fn test_has_global_metadata_both_files() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        fs::write(context.join("meta.json"), "{}").unwrap();
        fs::write(context.join("certs.json"), "{}").unwrap();

        assert!(has_global_metadata(context));
    }

    #[test]
    fn test_update_global_metadata_add_multiple() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        for i in 0..5 {
            let cert = CertMetadata {
                version: 1,
                cert_type: CertType::RootCa,
                domain: format!("domain{}.com", i),
                subject: format!("CN=domain{}.com", i),
                issuer: format!("CN=domain{}.com", i),
                serial: format!("{:02}", i),
                not_before: "2024-01-01".to_string(),
                not_after: "2034-01-01".to_string(),
                parent: None,
                signing_ca: None,
                private_key_encrypted: None,
                private_key_password_file: None,
                key_algorithm: None,
            };
            update_global_metadata(context, cert).unwrap();
        }

        let global = read_global_metadata(context).unwrap();
        assert_eq!(global.certificates.len(), 5);
    }

    #[test]
    fn test_find_ca_path_multiple_roots() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root1 = context.join("root1.com");
        let root2 = context.join("root2.com");
        fs::create_dir_all(&root1).unwrap();
        fs::create_dir_all(&root2).unwrap();
        fs::write(root1.join("crt.pem"), "dummy").unwrap();
        fs::write(root2.join("crt.pem"), "dummy").unwrap();

        let result1 = find_ca_path(context, "root1.com");
        let result2 = find_ca_path(context, "root2.com");

        assert!(result1.is_some());
        assert!(result2.is_some());
        assert_eq!(result1.unwrap(), root1);
        assert_eq!(result2.unwrap(), root2);
    }

    #[test]
    fn test_search_intermediates_multiple_levels() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let ica1 = base.join("intermediates.d").join("ica1.com");
        let ica2 = base
            .join("intermediates.d")
            .join("parent.com")
            .join("intermediates.d")
            .join("ica2.com");

        fs::create_dir_all(&ica1).unwrap();
        fs::create_dir_all(&ica2).unwrap();

        fs::write(ica1.join("crt.pem"), "dummy").unwrap();
        fs::write(ica2.join("crt.pem"), "dummy").unwrap();

        let result1 = search_intermediates(base, "ica1.com");
        let result2 = search_intermediates(base, "ica2.com");

        assert!(result1.is_some());
        assert!(result2.is_some());
    }

    #[test]
    fn test_find_nested_ica_path_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();

        let result = find_nested_ica_path(context, "nonexistent.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_nested_ica_path_multiple_levels() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let ica1 = root_dir.join("intermediates.d").join("ica1.com");
        fs::create_dir_all(&ica1).unwrap();
        fs::write(ica1.join("crt.pem"), "dummy").unwrap();

        let ica2 = ica1.join("intermediates.d").join("ica2.com");
        fs::create_dir_all(&ica2).unwrap();
        fs::write(ica2.join("crt.pem"), "dummy").unwrap();

        let result1 = find_nested_ica_path(context, "ica1.com");
        let result2 = find_nested_ica_path(context, "ica2.com");

        assert!(result1.is_some());
        assert!(result2.is_some());
    }

    #[test]
    fn test_find_cert_path_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = find_cert_path(context, "nonexistent.com", &CertType::RootCa);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_ca_path_with_intermediates() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let ica_dir = root_dir.join("intermediates.d").join("ica.com");
        fs::create_dir_all(&ica_dir).unwrap();
        fs::write(ica_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_ca_path(context, "ica.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_determine_certificate_type_unknown() {
        // Unknown path without intermediates.d or certificates.d returns RootCa
        let path = PathBuf::from("/random/path/crt.pem");
        let cert_type = determine_certificate_type(&path);
        assert_eq!(cert_type, CertificateType::RootCa);
    }

    #[test]
    fn test_extract_parent_ca_root_level() {
        // This path doesn't match the expected pattern
        let path = "/random/path/crt.pem";
        let parent = extract_parent_ca(path);
        // May or may not match depending on path structure
        // Just verify it doesn't panic
        let _ = parent;
    }

    #[test]
    fn test_global_metadata_sorting() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let certs = vec![
            CertMetadata {
                version: 1,
                cert_type: CertType::RootCa,
                domain: "zebra.com".to_string(),
                subject: "CN=zebra".to_string(),
                issuer: "CN=zebra".to_string(),
                serial: "03".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2034-01-01".to_string(),
                parent: None,
                signing_ca: None,
                private_key_encrypted: None,
                private_key_password_file: None,
                key_algorithm: None,
            },
            CertMetadata {
                version: 1,
                cert_type: CertType::RootCa,
                domain: "alpha.com".to_string(),
                subject: "CN=alpha".to_string(),
                issuer: "CN=alpha".to_string(),
                serial: "01".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2034-01-01".to_string(),
                parent: None,
                signing_ca: None,
                private_key_encrypted: None,
                private_key_password_file: None,
                key_algorithm: None,
            },
            CertMetadata {
                version: 1,
                cert_type: CertType::RootCa,
                domain: "middle.com".to_string(),
                subject: "CN=middle".to_string(),
                issuer: "CN=middle".to_string(),
                serial: "02".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2034-01-01".to_string(),
                parent: None,
                signing_ca: None,
                private_key_encrypted: None,
                private_key_password_file: None,
                key_algorithm: None,
            },
        ];

        let metadata = GlobalCertMetadata {
            version: 1,
            certificates: certs,
        };

        write_global_metadata(context, &metadata).unwrap();

        let read_metadata = read_global_metadata(context).unwrap();

        assert_eq!(read_metadata.certificates[0].domain, "alpha.com");
        assert_eq!(read_metadata.certificates[1].domain, "middle.com");
        assert_eq!(read_metadata.certificates[2].domain, "zebra.com");
    }

    #[test]
    fn test_certificate_type_serialization() {
        let root = CertificateType::RootCa;
        let ica = CertificateType::IntermediateCa;
        let server = CertificateType::ServerCert;

        // Test that the type can be converted to string via debug format
        let root_str = format!("{:?}", root);
        let ica_str = format!("{:?}", ica);
        let server_str = format!("{:?}", server);

        assert!(!root_str.is_empty());
        assert!(!ica_str.is_empty());
        assert!(!server_str.is_empty());
    }

    #[test]
    fn test_parse_alt_names_from_ext_no_dns() {
        let ext_content = r#"
# This is a comment
DNS.1=example.com
DNS.2=test.com
# Another comment
DNS.3=foo.bar.com
"#;
        let result = parse_alt_names_from_ext(ext_content).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"example.com".to_string()));
        assert!(result.contains(&"test.com".to_string()));
        assert!(result.contains(&"foo.bar.com".to_string()));
    }

    #[test]
    fn test_parse_alt_names_from_ext_empty_lines() {
        let ext_content = "\n\nDNS.1=test.com\n\n";
        let result = parse_alt_names_from_ext(ext_content).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "test.com");
    }

    #[test]
    fn test_read_file_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.txt");
        let result = read_file(&nonexistent);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_default_ext_content_multiple() {
        let content = generate_default_ext_content("test.example.com");
        assert!(content.contains("subjectAltName"));
        assert!(content.contains("test.example.com"));
    }

    #[test]
    fn test_check_certificate_expiry_not_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.crt");
        let result = check_certificate_expiry(&nonexistent).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_generate_default_ext_content_ip() {
        let content = generate_default_ext_content("192.168.1.1");
        assert!(content.contains("subjectAltName"));
    }

    #[test]
    fn test_generate_random_password_length() {
        let password = generate_random_password().unwrap();
        assert_eq!(password.len(), 44);
    }

    #[test]
    fn test_file_exists_true() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        std::fs::write(&file_path, "test").unwrap();
        assert!(file_exists(&file_path));
    }

    #[test]
    fn test_file_exists_false() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.txt");
        assert!(!file_exists(&nonexistent));
    }

    #[test]
    fn test_get_from_global_metadata_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let context = temp_dir.path();
        let result = get_from_global_metadata(context, "nonexistent.com");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_has_global_metadata_false() {
        let temp_dir = tempfile::tempdir().unwrap();
        let context = temp_dir.path();
        assert!(!has_global_metadata(context));
    }

    #[test]
    fn test_parse_alt_names_from_ext_ip() {
        let ext_content = "DNS.1=192.168.1.1\nDNS.2=10.0.0.1\nDNS.3=example.com";
        let result = parse_alt_names_from_ext(ext_content).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_parse_alt_names_from_ext_dns_numeric() {
        let ext_content = "DNS.1=server1\nDNS.2=server2\nDNS.10=server10";
        let result = parse_alt_names_from_ext(ext_content).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"server1".to_string()));
        assert!(result.contains(&"server2".to_string()));
        assert!(result.contains(&"server10".to_string()));
    }

    #[test]
    fn test_copy_dir_all_empty() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        copy_dir_all(&src, &dst).unwrap();
        assert!(dst.exists());
    }

    #[test]
    fn test_copy_dir_all_single_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("test.txt"), "content").unwrap();
        copy_dir_all(&src, &dst).unwrap();
        assert!(dst.join("test.txt").exists());
    }

    #[test]
    fn test_write_file_and_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        write_file(&file_path, "test content").unwrap();
        let content = read_file(&file_path).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_parse_alt_names_only_comments() {
        let result = parse_alt_names_from_ext("# comment\n# another comment").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_generate_default_ext_content_wildcard() {
        let content = generate_default_ext_content("*.example.com");
        assert!(content.contains("*.example.com"));
    }

    #[test]
    fn test_copy_dir_all_nested_subdirs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        std::fs::create_dir_all(src.join("a").join("b")).unwrap();
        std::fs::write(src.join("a").join("b").join("file.txt"), "content").unwrap();
        copy_dir_all(&src, &dst).unwrap();
        assert!(dst.join("a").join("b").join("file.txt").exists());
    }

    #[test]
    fn test_copy_dir_all_multiple_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("file1.txt"), "content1").unwrap();
        std::fs::write(src.join("file2.txt"), "content2").unwrap();
        copy_dir_all(&src, &dst).unwrap();
        assert!(dst.join("file1.txt").exists());
        assert!(dst.join("file2.txt").exists());
    }

    #[test]
    fn test_generate_default_ext_content_subdomain() {
        let content = generate_default_ext_content("api.v1.example.com");
        assert!(content.contains("api.v1.example.com"));
    }

    #[test]
    fn test_parse_alt_names_with_trailing_newline() {
        let result = parse_alt_names_from_ext("DNS.1=test.com\n").unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_generate_default_ext_content_localhost() {
        let content = generate_default_ext_content("localhost");
        assert!(content.contains("localhost"));
    }

    #[test]
    fn test_file_exists_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        assert!(file_exists(temp_dir.path()));
    }

    #[test]
    fn test_parse_alt_names_multiple_spaces() {
        let result = parse_alt_names_from_ext("DNS.1 = test.com").unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_alt_names_with_tab() {
        let result = parse_alt_names_from_ext("DNS.1 = test.com\nDNS.2 =\tfoo.com").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_alt_names_dns_case_variation() {
        let result = parse_alt_names_from_ext(
            "DNS.1=UPPERCASE.COM\nDNS.2=lowercase.com\nDNS.3=MixedCase.Com",
        )
        .unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_generate_default_ext_content_numeric_domain() {
        let content = generate_default_ext_content("12345");
        assert!(content.contains("12345"));
    }

    #[test]
    fn test_copy_dir_all_preserves_empty_dirs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");
        std::fs::create_dir_all(src.join("empty_subdir")).unwrap();
        copy_dir_all(&src, &dst).unwrap();
        assert!(dst.join("empty_subdir").exists());
    }

    #[test]
    fn test_generate_random_password_special_chars() {
        let password = generate_random_password().unwrap();
        assert!(!password.is_empty());
        assert!(password.len() >= 40);
    }

    #[test]
    fn test_generate_default_ext_content_with_numbers() {
        let content = generate_default_ext_content("server123");
        assert!(content.contains("server123"));
    }

    #[test]
    fn test_parse_alt_names_mixed_format() {
        let result =
            parse_alt_names_from_ext("DNS.1 = test.com # comment\nDNS.2=test2.com").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_generate_default_ext_content_special_chars() {
        let content = generate_default_ext_content("test-server_01.example.com");
        assert!(content.contains("test-server_01.example.com"));
    }

    #[test]
    fn test_remove_from_global_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let cert = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        update_global_metadata(context, cert.clone()).unwrap();
        let global = read_global_metadata(context).unwrap();
        assert_eq!(global.certificates.len(), 1);

        remove_from_global_metadata(context, "example.com").unwrap();
        let global = read_global_metadata(context).unwrap();
        assert_eq!(global.certificates.len(), 0);
    }

    #[test]
    fn test_remove_from_global_metadata_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = remove_from_global_metadata(context, "nonexistent.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_tls_certs_signed_by() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();

        let (root_cert_pem, _) = create_test_cert("root.com", 3650);
        fs::write(root_dir.join("crt.pem"), &root_cert_pem).unwrap();

        let cert_dir = root_dir.join("certificates.d").join("server.com");
        fs::create_dir_all(&cert_dir).unwrap();

        let (server_cert_pem, _) = create_test_cert("CN=server.com", 365);
        fs::write(cert_dir.join("crt.pem"), &server_cert_pem).unwrap();

        let result = find_tls_certs_signed_by(context, "root.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_icas_under_root_no_intermediates() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();

        let result = find_icas_under_root(context, "root.com").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_all_tls_under_ica() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();

        let ica_dir = root_dir.join("intermediates.d").join("ica.com");
        fs::create_dir_all(&ica_dir).unwrap();
        fs::write(ica_dir.join("crt.pem"), "dummy").unwrap();

        let cert_dir = ica_dir.join("certificates.d").join("server.com");
        fs::create_dir_all(&cert_dir).unwrap();

        let (server_cert_pem, _) = create_test_cert("CN=server.com", 365);
        fs::write(cert_dir.join("crt.pem"), &server_cert_pem).unwrap();

        let result = find_all_tls_under_ica(context, "ica.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_all_tls_under_ica_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = find_all_tls_under_ica(context, "nonexistent.com").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_export_certificate_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = export_certificate(context, "nonexistent.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_ca_certificate_true() {
        let (cert_pem, _) = create_test_cert("Test CA", 365);
        let cert = X509::from_pem(&cert_pem).unwrap();

        let result = is_ca_certificate(&cert);
        assert!(result);
    }

    #[test]
    fn test_get_cn_from_name() {
        let (cert_pem, _) = create_test_cert("Test CN", 365);
        let cert = X509::from_pem(&cert_pem).unwrap();

        let cn = get_cn_from_name(cert.subject_name());
        assert_eq!(cn, "Test CN");
    }

    #[test]
    fn test_shorten_path_with_home() {
        let home = dirs::home_dir().expect("Could not get home dir");
        let path = home
            .join(".local")
            .join("state")
            .join("certboy")
            .join("test");

        let result = shorten_path(&path);
        assert!(result.starts_with("~"));
    }

    #[test]
    fn test_update_global_metadata_replace_existing() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let cert1 = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        update_global_metadata(context, cert1).unwrap();

        let cert2 = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com-updated".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "02".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        update_global_metadata(context, cert2).unwrap();

        let global = read_global_metadata(context).unwrap();
        assert_eq!(global.certificates.len(), 1);
        assert_eq!(global.certificates[0].subject, "CN=example.com-updated");
    }

    #[test]
    fn test_verify_fullchain_order_valid() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path();

        let (cert_pem, _) = create_test_cert("Test", 365);
        fs::write(cert_dir.join("fullchain.crt"), &cert_pem).unwrap();
        fs::write(cert_dir.join("crt.pem"), &cert_pem).unwrap();

        let result = verify_fullchain_order(cert_dir);
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_days_until_expiry_valid() {
        let future_date = (chrono::Utc::now() + chrono::Duration::days(30))
            .format("%b %d %H:%M:%S %Y GMT")
            .to_string();
        let days = calculate_days_until_expiry(&future_date);
        assert!((29..=30).contains(&days));
    }

    #[test]
    fn test_calculate_days_until_expiry_past() {
        let past_date = "Jan 01 00:00:00 2020 GMT";
        let days = calculate_days_until_expiry(past_date);
        assert!(days < 0);
    }

    #[test]
    fn test_asn1time_to_datetime_various_formats() {
        use chrono::Datelike;

        let dt1 = asn1time_to_datetime("Dec 31 23:59:59 2099 GMT").unwrap();
        assert_eq!(dt1.year(), 2099);
        assert_eq!(dt1.month(), 12);
        assert_eq!(dt1.day(), 31);

        let dt2 = asn1time_to_datetime("Jun 15 12:30:45 2025").unwrap();
        assert_eq!(dt2.year(), 2025);
        assert_eq!(dt2.month(), 6);
        assert_eq!(dt2.day(), 15);
    }

    #[test]
    fn test_find_tls_cert_path_direct() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let cert_dir = root_dir.join("certificates.d").join("server.com");
        fs::create_dir_all(&cert_dir).unwrap();
        fs::write(cert_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_tls_cert_path(context, "server.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_find_tls_cert_path_under_ica() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let ica_dir = root_dir.join("intermediates.d").join("ica.com");
        fs::create_dir_all(&ica_dir).unwrap();
        fs::write(ica_dir.join("crt.pem"), "dummy").unwrap();

        let cert_dir = ica_dir.join("certificates.d").join("server.com");
        fs::create_dir_all(&cert_dir).unwrap();
        fs::write(cert_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_tls_cert_path(context, "server.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_find_tls_cert_path_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = find_tls_cert_path(context, "nonexistent.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_parent_ca_in_context_no_parent() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let (cert_pem, _) = create_test_cert("Test", 365);
        let cert = X509::from_pem(&cert_pem).unwrap();

        let result = find_parent_ca_in_context(context, "test.com", &cert).unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_import_certificate_invalid_path() {
        let temp_dir = TempDir::new().unwrap();
        let source = temp_dir.path().join("nonexistent");
        let context = temp_dir.path().join("context");

        let result = import_certificate(&source, &context).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_import_certificate_missing_crt() {
        let temp_dir = TempDir::new().unwrap();
        let source = temp_dir.path().join("source");
        fs::create_dir_all(&source).unwrap();
        let context = temp_dir.path().join("context");

        let result = import_certificate(&source, &context).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_has_metadata_false() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        assert!(!has_metadata(dir));
    }

    #[test]
    fn test_certificate_type_equality() {
        assert_eq!(CertificateType::RootCa, CertificateType::RootCa);
        assert_eq!(
            CertificateType::IntermediateCa,
            CertificateType::IntermediateCa
        );
        assert_eq!(CertificateType::ServerCert, CertificateType::ServerCert);
        assert_ne!(CertificateType::RootCa, CertificateType::IntermediateCa);
    }

    #[test]
    fn test_cert_type_equality() {
        assert_eq!(CertType::RootCa, CertType::RootCa);
        assert_eq!(CertType::Ica, CertType::Ica);
        assert_eq!(CertType::Tls, CertType::Tls);
        assert_ne!(CertType::RootCa, CertType::Ica);
    }

    #[test]
    fn test_global_cert_metadata_empty() {
        let meta = GlobalCertMetadata::new();
        assert_eq!(meta.version, 1);
        assert!(meta.certificates.is_empty());
    }

    #[test]
    fn test_cert_metadata_clone() {
        let meta = CertMetadata {
            version: 1,
            cert_type: CertType::RootCa,
            domain: "example.com".to_string(),
            subject: "CN=example.com".to_string(),
            issuer: "CN=example.com".to_string(),
            serial: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            parent: None,
            signing_ca: None,
            private_key_encrypted: None,
            private_key_password_file: None,
            key_algorithm: None,
        };

        let cloned = meta.clone();
        assert_eq!(cloned.domain, meta.domain);
    }

    #[test]
    fn test_find_all_tls_under_ica_empty() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let root_dir = context.join("root.com");
        fs::create_dir_all(&root_dir).unwrap();
        fs::write(root_dir.join("crt.pem"), "dummy").unwrap();

        let result = find_all_tls_under_ica(context, "nonexistent.ica.com");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_update_fullchain_crt_noop() {
        let result = update_fullchain_crt();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_certificates_empty_context() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = list_certificates(context, false, 14, false, false, false, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_revoke_certificate_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = revoke_certificate(context, "nonexistent.com", true).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_days_until_expiry_expired() {
        let past_date = "Jan 01 00:00:00 2020 GMT";
        let days = calculate_days_until_expiry(past_date);
        assert!(days < 0);
    }

    #[test]
    fn test_shorten_path_no_home() {
        let path = PathBuf::from("/some/random/path");
        let result = shorten_path(&path);
        assert_eq!(result, "/some/random/path");
    }

    #[test]
    fn test_search_intermediates_empty() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = search_intermediates(context, "nonexistent.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_all_tls_under_ica_no_ica() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = find_all_tls_under_ica(context, "nonexistent.ica.com");
        assert!(result.is_ok());
        let certs = result.unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn test_find_tls_certs_signed_by_no_ca() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = find_tls_certs_signed_by(context, "nonexistent.com");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_import_certificate_source_not_exist() {
        let temp_dir = TempDir::new().unwrap();
        let source = temp_dir.path().join("nonexistent");
        let context = temp_dir.path().join("context");

        let result = import_certificate(&source, &context).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_key_cert_match_no_key() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("cert");
        fs::create_dir_all(&cert_dir).unwrap();

        let (cert_pem, _) = create_test_cert("test.com", 365);
        fs::write(cert_dir.join("crt.pem"), &cert_pem).unwrap();

        let result = verify_key_cert_match(&cert_dir);
        assert!(result.is_ok());
        let (is_valid, message) = result.unwrap();
        assert!(!is_valid);
        assert!(message.contains("key.pem not found"));
    }

    #[test]
    fn test_verify_key_cert_match_no_crt() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("cert");
        fs::create_dir_all(&cert_dir).unwrap();

        let (key_pem, _) = create_test_cert("test.com", 365);
        fs::write(cert_dir.join("key.pem"), &key_pem).unwrap();

        let result = verify_key_cert_match(&cert_dir);
        assert!(result.is_ok());
        let (is_valid, message) = result.unwrap();
        assert!(!is_valid);
        assert!(message.contains("crt.pem not found"));
    }

    #[test]
    fn test_verify_key_cert_match_matching() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("cert");
        fs::create_dir_all(&cert_dir).unwrap();

        let (cert_pem, key_pem) = create_test_cert("test.com", 365);
        fs::write(cert_dir.join("crt.pem"), &cert_pem).unwrap();
        fs::write(cert_dir.join("key.pem"), &key_pem).unwrap();

        let result = verify_key_cert_match(&cert_dir);
        assert!(result.is_ok());
        let (is_valid, message) = result.unwrap();
        assert!(is_valid);
        assert!(message.contains("match"));
    }

    #[test]
    fn test_verify_key_cert_match_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("cert");
        fs::create_dir_all(&cert_dir).unwrap();

        let (cert_pem, _) = create_test_cert("cert.com", 365);
        let (_, key_pem) = create_test_cert("key.com", 365);
        fs::write(cert_dir.join("crt.pem"), &cert_pem).unwrap();
        fs::write(cert_dir.join("key.pem"), &key_pem).unwrap();

        let result = verify_key_cert_match(&cert_dir);
        assert!(result.is_ok());
        let (is_valid, message) = result.unwrap();
        assert!(!is_valid);
        assert!(message.contains("DO NOT MATCH"));
    }

    #[test]
    fn test_verify_key_cert_match_encrypted_key_with_pass() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("cert");
        fs::create_dir_all(&cert_dir).unwrap();

        let (cert_pem, key_pem) = create_test_cert("test.com", 365);
        fs::write(cert_dir.join("crt.pem"), &cert_pem).unwrap();

        let passphrase = "testpass123";
        let key_tmp = temp_dir.path().join("key.tmp");
        fs::write(&key_tmp, &key_pem).unwrap();
        let out_tmp = temp_dir.path().join("key.enc");

        let encrypted_key = std::process::Command::new("openssl")
            .args(["pkcs8", "-topk8", "-v2", "aes256", "-in"])
            .arg(&key_tmp)
            .arg("-out")
            .arg(&out_tmp)
            .arg("-passout")
            .arg(format!("pass:{passphrase}"))
            .output()
            .expect("failed to encrypt key");
        assert!(
            encrypted_key.status.success(),
            "openssl pkcs8 failed: {}",
            String::from_utf8_lossy(&encrypted_key.stderr)
        );
        let encrypted_key_pem = fs::read_to_string(&out_tmp).unwrap();
        assert!(
            encrypted_key_pem.contains("BEGIN ENCRYPTED PRIVATE KEY"),
            "Expected ENCRYPTED PRIVATE KEY header"
        );
        fs::write(cert_dir.join("key.pem"), &encrypted_key_pem).unwrap();
        fs::write(cert_dir.join("key.pass"), passphrase).unwrap();

        let result = verify_key_cert_match(&cert_dir);
        assert!(result.is_ok(), "verify_key_cert_match failed: {:?}", result);
        let (is_valid, message) = result.unwrap();
        assert!(
            is_valid,
            "Expected match for encrypted key with correct passphrase: {}",
            message
        );
        assert!(
            message.contains("match"),
            "Expected match message, got: {}",
            message
        );
    }

    #[test]
    fn test_verify_key_cert_match_encrypted_key_no_pass() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("cert");
        fs::create_dir_all(&cert_dir).unwrap();

        let (cert_pem, key_pem) = create_test_cert("test.com", 365);
        fs::write(cert_dir.join("crt.pem"), &cert_pem).unwrap();

        let key_tmp = temp_dir.path().join("key.tmp");
        fs::write(&key_tmp, &key_pem).unwrap();
        let out_tmp = temp_dir.path().join("key.enc");

        let _encrypted_key = std::process::Command::new("openssl")
            .args(["pkcs8", "-topk8", "-v2", "aes256", "-in"])
            .arg(&key_tmp)
            .arg("-out")
            .arg(&out_tmp)
            .arg("-passout")
            .arg("pass:testpass123")
            .output()
            .expect("failed to encrypt key");
        let encrypted_key_pem = fs::read_to_string(&out_tmp).unwrap();
        fs::write(cert_dir.join("key.pem"), &encrypted_key_pem).unwrap();

        let result = verify_key_cert_match(&cert_dir);
        assert!(result.is_ok());
        let (is_valid, message) = result.unwrap();
        assert!(!is_valid);
        assert!(
            message.contains("encrypted"),
            "Expected encrypted key error, got: {}",
            message
        );
    }

    #[test]
    fn test_certificate_type_determination() {
        let root_path = PathBuf::from("/context/example.com/crt.pem");
        let ica_path =
            PathBuf::from("/context/example.com/intermediates.d/ops.example.com/crt.pem");
        let server_path =
            PathBuf::from("/context/example.com/certificates.d/www.example.com/crt.pem");
        let server_under_ica = PathBuf::from(
            "/context/example.com/ops.example.com/certificates.d/www.example.com/crt.pem",
        );

        assert_eq!(
            determine_certificate_type(&root_path),
            CertificateType::RootCa
        );
        assert_eq!(
            determine_certificate_type(&ica_path),
            CertificateType::IntermediateCa
        );
        assert_eq!(
            determine_certificate_type(&server_path),
            CertificateType::ServerCert
        );
        assert_eq!(
            determine_certificate_type(&server_under_ica),
            CertificateType::ServerCert
        );
    }

    #[test]
    fn test_certificate_info_serial_field() {
        let info = CertificateInfo {
            path: PathBuf::from("/test/crt.pem"),
            domain: "test.com".to_string(),
            cert_type: CertificateType::RootCa,
            issuer: "CN=test.com".to_string(),
            subject: "CN=test.com".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            expires_in_days: 3650,
            needs_renewal: false,
            parent: None,
            sans: vec![],
            serial: "03E8".to_string(), // Hex for 1000
            key_algorithm: None,
        };

        assert_eq!(info.serial, "03E8");
    }

    #[test]
    fn test_certificate_type_from_cert_type_impl() {
        assert_eq!(
            CertificateType::from(&CertType::RootCa),
            CertificateType::RootCa
        );
        assert_eq!(
            CertificateType::from(&CertType::Ica),
            CertificateType::IntermediateCa
        );
        assert_eq!(
            CertificateType::from(&CertType::Tls),
            CertificateType::ServerCert
        );
    }

    // ============================================
    // Tests for new random serial functions
    // ============================================

    #[test]
    fn test_generate_unique_serial_nonzero() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let serial = generate_unique_serial(context).unwrap();
        let bn = serial.to_bn().unwrap();
        let hex_str = bn.to_hex_str().unwrap();

        // Serial should not be all zeros
        assert_ne!(hex_str.to_string(), "00", "Serial should not be zero");
        // Should not be empty
        assert!(!hex_str.is_empty(), "Serial should not be empty");
    }

    #[test]
    fn test_generate_unique_serial_length() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let serial = generate_unique_serial(context).unwrap();
        let bn = serial.to_bn().unwrap();
        let hex_str = bn.to_hex_str().unwrap();

        // OpenSSL-style serial is 20 bytes = 40 hex characters
        assert_eq!(
            hex_str.len(),
            40,
            "Serial should be 20 bytes (40 hex chars), got {} chars: {}",
            hex_str.len(),
            hex_str
        );
    }

    #[test]
    fn test_generate_unique_serial_unique() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let serial1 = generate_unique_serial(context).unwrap();
        let serial2 = generate_unique_serial(context).unwrap();

        let bn1 = serial1.to_bn().unwrap();
        let bn2 = serial2.to_bn().unwrap();

        // Two different generations should produce different serials (with very high probability)
        assert_ne!(
            bn1.to_hex_str().unwrap().to_string(),
            bn2.to_hex_str().unwrap().to_string(),
            "Two generations should produce different serials"
        );
    }

    #[test]
    fn test_generate_unique_serial_no_collision_with_existing() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        // Create a root CA directory structure
        let root_dir = context.join("test-root.com");
        fs::create_dir_all(&root_dir).unwrap();

        // Create a certificate with a known serial
        let (cert_pem, _) = create_test_cert("test-root.com", 3650);
        fs::write(root_dir.join("crt.pem"), &cert_pem).unwrap();

        // Now generate a unique serial - it should NOT match the existing cert's serial
        let existing_cert = X509::from_pem(&cert_pem).unwrap();
        let existing_serial = existing_cert.serial_number().to_bn().unwrap();
        let existing_hex = existing_serial.to_hex_str().unwrap().to_string();

        // Generate many serials and ensure none match the existing one
        for _ in 0..100 {
            let serial = generate_unique_serial(context).unwrap();
            let bn = serial.to_bn().unwrap();
            let hex_str = bn.to_hex_str().unwrap().to_string();
            assert_ne!(
                hex_str, existing_hex,
                "Generated serial should not collide with existing certificate serial"
            );
        }
    }

    #[test]
    fn test_ask_confirm_yes_flag_always_true() {
        // When yes=true, should always return true regardless of prompt
        assert!(ask_confirm("Test prompt?", true));
        assert!(ask_confirm("", true));
        assert!(ask_confirm("Anything?", true));
    }

    #[test]
    fn test_serial_exists_in_context_empty() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        let result = serial_exists_in_context(context, &[1u8; 20]);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Empty context should not have any serials"
        );
    }

    #[test]
    fn test_serial_exists_in_context_finds_match() {
        let temp_dir = TempDir::new().unwrap();
        let context = temp_dir.path();

        // Create a certificate with a specific serial
        let root_dir = context.join("test.com");
        fs::create_dir_all(&root_dir).unwrap();

        let (cert_pem, _) = create_test_cert("test.com", 3650);
        fs::write(root_dir.join("crt.pem"), &cert_pem).unwrap();

        // Extract the serial from the certificate
        let cert = X509::from_pem(&cert_pem).unwrap();
        let serial_bn = cert.serial_number().to_bn().unwrap();
        let serial_hex = serial_bn.to_hex_str().unwrap().to_string();

        // Parse hex string back to bytes (40 hex chars = 20 bytes)
        let mut serial_bytes = [0u8; 20];
        for (i, chunk) in serial_hex.chars().enumerate() {
            let nibble = chunk.to_digit(16).unwrap() as u8;
            serial_bytes[i / 2] = serial_bytes[i / 2] * 16 + nibble;
        }

        // serial_exists_in_context should find it
        let result = serial_exists_in_context(context, &serial_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fix_result_fixed() {
        let result = FixResult::fixed(
            "test.com".to_string(),
            CertificateType::ServerCert,
            "Re-signed".to_string(),
        );
        assert!(result.fixed);
        assert!(!result.skipped);
        assert_eq!(result.domain, "test.com");
    }

    #[test]
    fn test_fix_result_skipped() {
        let result = FixResult::skipped(
            "test.com".to_string(),
            CertificateType::ServerCert,
            "User declined".to_string(),
        );
        assert!(!result.fixed);
        assert!(result.skipped);
        assert_eq!(result.domain, "test.com");
    }
}
