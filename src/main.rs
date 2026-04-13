use clap::CommandFactory;
use clap::Parser;
use clap::Subcommand;
use clap_complete::Shell;
use std::path::PathBuf;
use tracing::{error, info, Level};

mod ca;
mod cert;
mod ica;
mod types;
mod utils;

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum KeyAlgorithmArg {
    Rsa,
    Ecdsa,
}

impl From<KeyAlgorithmArg> for utils::KeyAlgorithm {
    fn from(value: KeyAlgorithmArg) -> Self {
        match value {
            KeyAlgorithmArg::Rsa => utils::KeyAlgorithm::Rsa,
            KeyAlgorithmArg::Ecdsa => utils::KeyAlgorithm::EcdsaP256,
        }
    }
}

#[derive(Parser)]
#[command(name = "certboy")]
#[command(
    about = "Unified certificate management tool - Create Root CAs, Intermediate CAs, and server certificates"
)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Domain name for certificate/CA (can be specified multiple times for SAN)
    #[arg(short, long, value_name = "DOMAIN")]
    domain: Vec<String>,

    /// Domain arguments (merged with -d/--domain)
    #[arg(value_name = "DOMAIN", num_args = 0.., requires = "ca")]
    domain_args: Vec<String>,

    /// Common Name for certificate (required for Root CA and ICA)
    #[arg(long, value_name = "CN")]
    cn: Option<String>,

    /// Country code (default: CN)
    #[arg(long, value_name = "COUNTRY", default_value = "CN")]
    country: String,

    /// Parent CA to sign with (Root CA or ICA name)
    #[arg(short, long, value_name = "CA")]
    ca: Option<String>,

    /// Create a Root CA instead of signing a certificate
    #[arg(short, long)]
    root_ca: bool,

    /// Force re-sign existing certificate
    #[arg(short, long)]
    force: bool,

    /// Encrypt generated TLS private key with a passphrase (stored in pass.key)
    #[arg(long, default_value_t = false)]
    encrypt_key: bool,

    /// Key algorithm for Root CA (default: ecdsa)
    #[arg(long, value_enum, default_value_t = KeyAlgorithmArg::Ecdsa)]
    key_algorithm: KeyAlgorithmArg,

    /// Expiration in days for certificate/CA (overrides default: 7300 Root CA, 3650 ICA, 1095 TLS)
    #[arg(
        short = 'e',
        long,
        value_name = "DAYS",
        help = "Expiration in days. Common values: 730 (2y), 1095 (3y), 1825 (5y), 3650 (10y), 7300 (20y)"
    )]
    expiration: Option<u32>,

    /// Context path for certificates (default: $XDG_STATE_HOME/certboy or ~/.local/state/certboy; env: CERTBOY_CONTEXT; legacy env: CERTM_CONTEXT, BW_MKCERT_CONTEXT)
    #[arg(short = 'C', long, value_name = "PATH")]
    context: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Verbose level (-v=info, -vv=debug, -vvv=trace)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Check certificates in the context
    Check {
        /// Check for certificates needing renewal
        #[arg(short, long)]
        renew: bool,

        /// Expiration alert threshold in days (default: 14 days / 2 weeks)
        #[arg(short = 'E', long, value_name = "DAYS", default_value = "14")]
        expiration_alert: u32,

        /// Show detailed information including DNS names and IP addresses for TLS certificates
        #[arg(long)]
        detail: bool,

        /// Automatically fix certificates with issues (duplicate serials, serial 0, wrong fullchain order)
        #[arg(long)]
        auto_fix: bool,

        /// Skip confirmation prompts (use with auto-fix to apply fixes without prompting)
        #[arg(short = 'y', long)]
        yes: bool,

        /// Verify that private key matches certificate for TLS certs using OpenSSL
        #[arg(long)]
        verify_openssl: bool,

        /// Context path (default: $XDG_STATE_HOME/certboy or ~/.local/state/certboy; env: CERTBOY_CONTEXT; legacy env: CERTM_CONTEXT, BW_MKCERT_CONTEXT)
        #[arg(short = 'C', long, value_name = "PATH")]
        context: Option<PathBuf>,
    },

    /// Import a Root CA or ICA folder to create a new context
    #[command(long_about = "\
Import a Root CA or ICA folder to create a new context.

Usage:
  certboy import <path> --context <path>
  certboy import <path> [<path>...] --context <path>

Examples:
  # Import a Root CA folder
  certboy import /path/to/root-ca-folder --context /path/to/new/context

  # Import an ICA folder (requires context with existing Root CA)
  certboy import /path/to/ica.ExampleOrg --context /path/to/existing/context

  # Import multiple folders at once
  certboy import /path/to/ca1 /path/to/ca2 --context /path/to/new/context")]
    Import {
        /// Paths to the Root CA or ICA folders to import (multiple allowed)
        #[arg(value_name = "PATH")]
        source: Vec<PathBuf>,

        /// Context path for the new certificate store
        #[arg(short = 'C', long, value_name = "PATH")]
        context: Option<PathBuf>,
    },

    /// Export server certificate and key to current directory
    #[command(long_about = "\
Export server certificate and key to current directory.

Usage:
  certboy export <domain> [--context <path>]

Examples:
  # Export a server certificate
  certboy export www.example.com

  # Export with custom context
  certboy export www.example.com --context /path/to/context

  # Export multiple certificates (run multiple times)
  certboy export www.example.com
  certboy export api.example.com")]
    Export {
        /// Domain of the server certificate to export
        #[arg(value_name = "DOMAIN")]
        domain: String,

        /// Context path (default: $XDG_STATE_HOME/certboy or ~/.local/state/certboy; env: CERTBOY_CONTEXT; legacy env: CERTM_CONTEXT, BW_MKCERT_CONTEXT)
        #[arg(short = 'C', long, value_name = "PATH")]
        context: Option<PathBuf>,
    },

    /// Generate shell completion scripts for bash, zsh, fish, or powershell
    #[command(long_about = "\
Generate shell completion scripts for bash, zsh, fish, or powershell.

Usage:
  certboy completion bash
  certboy completion zsh
  certboy completion fish
  certboy completion powershell

Examples:

Bash (system-wide):
  certboy completion bash > /etc/bash_completion.d/certboy

Bash (user-specific):
  mkdir -p ~/.local/share/certboy/completions
  certboy completion bash > ~/.local/share/certboy/completions/certboy
  Add to ~/.bashrc: source ~/.local/share/certboy/completions/certboy

Zsh:
  certboy completion zsh > ~/.zsh/completions/_certboy
  Add to ~/.zshrc: fpath=(~/.zsh/completions $fpath) && autoload -Uz compinit

Fish:
  certboy completion fish > ~/.config/fish/completions/certboy.fish")]
    Completion {
        /// Shell to generate completion for
        #[arg(value_name = "SHELL")]
        shell: String,
    },

    /// Revoke (remove) certificates by domain name
    #[command(long_about = "\
Revoke and remove certificates from the context.

Usage:
  certboy revoke <domain> [<domain>...]

For TLS certificates: removes the certificate directory.
For Intermediate CA (ICA): removes the ICA and all TLS certificates signed by it.
For Root CA: removes the entire root CA directory including all ICAs and certificates.

WARNING: This operation is irreversible. Certificates will be permanently deleted.

Examples:
  # Revoke a TLS certificate
  certboy revoke www.example.com

  # Revoke multiple certificates
  certboy revoke www.example.com api.example.com

  # Revoke an ICA (will show confirmation with impacted certs)
  certboy revoke ica.example.com")]
    Revoke {
        /// Domain names of certificates to revoke (can specify multiple)
        #[arg(value_name = "DOMAIN", required = true)]
        domains: Vec<String>,

        /// Context path (default: $XDG_STATE_HOME/certboy or ~/.local/state/certboy; env: CERTBOY_CONTEXT; legacy env: CERTM_CONTEXT, BW_MKCERT_CONTEXT)
        #[arg(short = 'C', long, value_name = "PATH")]
        context: Option<PathBuf>,

        /// Skip confirmation prompts (use with caution)
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

fn get_log_level(verbose: u8) -> Level {
    match verbose {
        0 => {
            if let Ok(level_str) = std::env::var("LOGLEVEL") {
                match level_str.to_lowercase().as_str() {
                    "trace" => Level::TRACE,
                    "debug" => Level::DEBUG,
                    "info" => Level::INFO,
                    "warn" | "warning" => Level::WARN,
                    "error" => Level::ERROR,
                    _ => Level::WARN,
                }
            } else {
                Level::WARN
            }
        }
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    }
}

fn get_context(context: Option<PathBuf>) -> PathBuf {
    if let Some(path) = context {
        return path;
    }

    if let Some(path) = std::env::var_os("CERTBOY_CONTEXT").map(PathBuf::from) {
        return path;
    }

    if let Some(path) = std::env::var_os("CERTM_CONTEXT").map(PathBuf::from) {
        return path;
    }

    if let Some(path) = std::env::var_os("BW_MKCERT_CONTEXT").map(PathBuf::from) {
        return path;
    }

    let home = dirs::home_dir().expect("Could not determine home directory");
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local").join("state"));
    state_home.join("certboy")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse().unwrap_or_else(|e| e.exit());

    let level = get_log_level(cli.verbose);
    tracing_subscriber::fmt().with_max_level(level).init();

    // Handle subcommands
    if let Some(command) = cli.command {
        match command {
            Commands::Check {
                renew,
                expiration_alert,
                detail,
                auto_fix,
                yes,
                verify_openssl,
                context: cmd_context,
            } => {
                let context = get_context(cmd_context.or(cli.context));
                info!("Executing check command");

                match utils::list_certificates(
                    &context,
                    renew,
                    expiration_alert,
                    detail,
                    auto_fix,
                    yes,
                    verify_openssl,
                )
                .await
                {
                    Ok(()) => {
                        info!("Check completed successfully");
                    }
                    Err(e) => {
                        error!("Failed to check certificates: {}", e);
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }

            Commands::Import {
                source,
                context: cmd_context,
            } => {
                let context = get_context(cmd_context.or(cli.context));
                info!("Importing certificates from: {:?}", source);

                // Validate all paths first
                for path in &source {
                    if !path.exists() {
                        eprintln!("Error: Source path does not exist: {:?}", path);
                        std::process::exit(1);
                    }
                    let crt_path = path.join("crt.pem");
                    if !crt_path.exists() {
                        eprintln!("Error: Source path is not a valid CA/ICA folder (missing crt.pem): {:?}", path);
                        std::process::exit(1);
                    }
                }

                // Import one by one
                let mut imported_count = 0;
                for path in &source {
                    match utils::import_certificate(path, &context).await {
                        Ok(()) => {
                            imported_count += 1;
                        }
                        Err(e) => {
                            error!("Failed to import {:?}: {}", path, e);
                            eprintln!("Warning: Failed to import {:?}: {}", path, e);
                        }
                    }
                }

                if imported_count > 0 {
                    info!("Imported {} certificate(s) successfully", imported_count);
                    println!(
                        "Import completed: {} certificate(s) imported",
                        imported_count
                    );
                } else {
                    eprintln!("Error: No certificates were imported");
                    std::process::exit(1);
                }
                return Ok(());
            }

            Commands::Export {
                domain,
                context: cmd_context,
            } => {
                let context = get_context(cmd_context.or(cli.context));
                info!("Exporting certificate for domain: {}", domain);

                match utils::export_certificate(&context, &domain) {
                    Ok(()) => {
                        info!("Export completed successfully");
                        println!("Certificate exported: {}.crt and {}.key", domain, domain);
                    }
                    Err(e) => {
                        error!("Failed to export certificate: {}", e);
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }

            Commands::Completion { shell } => {
                let shell: Shell = shell.parse::<Shell>()?;
                let mut app = Cli::command();
                clap_complete::generate(shell, &mut app, "certboy", &mut std::io::stdout());
                return Ok(());
            }

            Commands::Revoke {
                domains,
                context: cmd_context,
                yes,
            } => {
                let context = get_context(cmd_context.or(cli.context));
                info!("Revoking certificates for domains: {:?}", domains);

                for domain in &domains {
                    match utils::revoke_certificate(&context, domain, yes).await {
                        Ok(()) => {
                            info!("Successfully revoked certificate: {}", domain);
                        }
                        Err(e) => {
                            error!("Failed to revoke certificate {}: {}", domain, e);
                            eprintln!("Error: {}", e);
                        }
                    }
                }
                return Ok(());
            }
        }
    }

    let mut domains = cli.domain.clone();
    domains.extend(cli.domain_args.clone());
    let mut seen = std::collections::HashSet::new();
    domains.retain(|d| seen.insert(d.clone()));

    if cli.root_ca {
        // Root CA mode
        let context = get_context(cli.context);

        if !context.exists() {
            std::fs::create_dir_all(&context)?;
            info!("Created context directory: {:?}", context);
        }

        if domains.is_empty() {
            eprintln!("Error: Domain is required for Root CA creation");
            std::process::exit(1);
        }

        let domain = &domains[0];
        let cn = cli.cn.as_deref().unwrap_or(domain);
        let country = &cli.country;

        info!(
            "Initializing root CA for domain: {} with CN: {} and Country: {}",
            domain, cn, country
        );

        match ca::init_root_ca(
            &context,
            domain,
            cn,
            country,
            cli.key_algorithm.into(),
            cli.expiration,
        )
        .await
        {
            Ok(()) => {
                info!("Root CA initialization completed successfully");
                println!("Root CA initialization completed successfully");
            }
            Err(e) => {
                error!("Failed to initialize root CA: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(ca) = &cli.ca {
        // ICA or Certificate signing mode
        let context = get_context(cli.context);

        if !context.exists() {
            std::fs::create_dir_all(&context)?;
            info!("Created context directory: {:?}", context);
        }

        if domains.is_empty() {
            eprintln!("Error: Domain is required for certificate signing");
            std::process::exit(1);
        }

        let domain = &domains[0];
        let altnames: Option<Vec<String>> = if domains.len() > 1 {
            Some(domains[1..].to_vec())
        } else {
            None
        };

        // Check if it's ICA (has cn) or regular cert
        if let Some(cn) = &cli.cn {
            // ICA mode
            let country = &cli.country;
            info!(
                "Signing ICA for domain: {} with CA: {} and CN: {}",
                domain, ca, cn
            );

            match ica::sign_ica(&context, domain, ca, cn, country, cli.expiration).await {
                Ok(()) => {
                    info!("ICA signing completed successfully");
                    println!("ICA signing completed successfully");
                }
                Err(e) => {
                    error!("Failed to sign ICA: {}", e);
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            // Certificate signing mode
            info!(
                "Signing certificate for domain: {} with CA: {}, force: {}",
                domain, ca, cli.force
            );

            match cert::sign_cert(
                &context,
                domain,
                ca,
                cli.force,
                altnames.as_deref(),
                cli.expiration,
                cli.encrypt_key,
            )
            .await
            {
                Ok(()) => {
                    info!("Certificate signing completed successfully");
                    println!("Certificate signing completed successfully");
                }
                Err(e) => {
                    error!("Failed to sign certificate: {}", e);
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    } else {
        let context = get_context(cli.context);
        info!("Executing check command (default behavior)");

        match utils::list_certificates(&context, false, 14, false, false, false, false).await {
            Ok(()) => {
                info!("Check completed successfully");
            }
            Err(e) => {
                error!("Failed to check certificates: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    info!("certboy completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::PathBuf;
    use tracing::Level;

    #[test]
    #[serial]
    fn test_get_log_level_default() {
        std::env::remove_var("LOGLEVEL");
        let level = get_log_level(0);
        assert_eq!(level, Level::WARN);
    }

    #[test]
    fn test_get_log_level_verbose_1() {
        let level = get_log_level(1);
        assert_eq!(level, Level::INFO);
    }

    #[test]
    fn test_get_log_level_verbose_2() {
        let level = get_log_level(2);
        assert_eq!(level, Level::DEBUG);
    }

    #[test]
    fn test_get_log_level_verbose_3() {
        let level = get_log_level(3);
        assert_eq!(level, Level::TRACE);
    }

    #[test]
    #[serial]
    fn test_get_log_level_env_trace() {
        std::env::remove_var("LOGLEVEL");
        let _guard = EnvGuard::new("LOGLEVEL", "trace");
        let level = get_log_level(0);
        assert_eq!(level, Level::TRACE);
    }

    #[test]
    #[serial]
    fn test_get_log_level_env_debug() {
        std::env::remove_var("LOGLEVEL");
        let _guard = EnvGuard::new("LOGLEVEL", "debug");
        let level = get_log_level(0);
        assert_eq!(level, Level::DEBUG);
    }

    #[test]
    #[serial]
    fn test_get_log_level_env_info() {
        std::env::remove_var("LOGLEVEL");
        let _guard = EnvGuard::new("LOGLEVEL", "info");
        let level = get_log_level(0);
        assert_eq!(level, Level::INFO);
    }

    #[test]
    #[serial]
    fn test_get_log_level_env_warn() {
        std::env::remove_var("LOGLEVEL");
        let _guard = EnvGuard::new("LOGLEVEL", "warn");
        let level = get_log_level(0);
        assert_eq!(level, Level::WARN);
    }

    #[test]
    #[serial]
    fn test_get_log_level_env_warning() {
        std::env::remove_var("LOGLEVEL");
        let _guard = EnvGuard::new("LOGLEVEL", "warning");
        let level = get_log_level(0);
        assert_eq!(level, Level::WARN);
    }

    #[test]
    #[serial]
    fn test_get_log_level_env_error() {
        std::env::remove_var("LOGLEVEL");
        let _guard = EnvGuard::new("LOGLEVEL", "error");
        let level = get_log_level(0);
        assert_eq!(level, Level::ERROR);
    }

    #[test]
    #[serial]
    fn test_get_log_level_env_invalid() {
        std::env::remove_var("LOGLEVEL");
        let _guard = EnvGuard::new("LOGLEVEL", "invalid_level");
        let level = get_log_level(0);
        assert_eq!(level, Level::WARN);
    }

    #[test]
    fn test_get_context_with_path() {
        let path = PathBuf::from("/custom/path");
        let result = get_context(Some(path.clone()));
        assert_eq!(result, path);
    }

    #[test]
    fn test_get_context_default() {
        let _guard = EnvGuard::new("CERTBOY_CONTEXT", "/custom/default");
        let result = get_context(None);
        assert_eq!(result, PathBuf::from("/custom/default"));
    }

    #[test]
    fn test_cli_command_factory() {
        // Test that CLI can be built without panicking
        let cmd = Cli::command();
        assert_eq!(cmd.get_name(), "certboy");
    }

    #[test]
    fn test_cli_parse_root_ca() {
        let cli = Cli::parse_from([
            "certboy",
            "--domain",
            "test.com",
            "--cn",
            "Test CA",
            "--root-ca",
        ]);
        assert_eq!(cli.domain, vec!["test.com"]);
        assert_eq!(cli.cn, Some("Test CA".to_string()));
        assert!(cli.root_ca);
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_parse_with_ca() {
        let cli = Cli::parse_from([
            "certboy",
            "--ca",
            "root.com",
            "--domain",
            "www.example.com",
            "--domain",
            "api.example.com",
        ]);
        assert_eq!(cli.ca, Some("root.com".to_string()));
        assert_eq!(cli.domain, vec!["www.example.com", "api.example.com"]);
        assert!(!cli.root_ca);
    }

    #[test]
    fn test_cli_parse_check_command() {
        let cli = Cli::parse_from([
            "certboy",
            "check",
            "--renew",
            "--expiration-alert",
            "30",
            "--detail",
        ]);
        assert!(cli.command.is_some());
        match cli.command.unwrap() {
            Commands::Check {
                renew,
                expiration_alert,
                detail,
                ..
            } => {
                assert!(renew);
                assert_eq!(expiration_alert, 30);
                assert!(detail);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_parse_import_command() {
        let cli = Cli::parse_from(["certboy", "import", "/path/to/ca"]);
        match cli.command.unwrap() {
            Commands::Import { source, .. } => {
                assert_eq!(source.len(), 1);
                assert_eq!(source[0], PathBuf::from("/path/to/ca"));
            }
            _ => panic!("Expected Import command"),
        }
    }

    #[test]
    fn test_cli_parse_export_command() {
        let cli = Cli::parse_from(["certboy", "export", "www.example.com"]);
        match cli.command.unwrap() {
            Commands::Export { domain, .. } => {
                assert_eq!(domain, "www.example.com");
            }
            _ => panic!("Expected Export command"),
        }
    }

    #[test]
    fn test_cli_parse_completion_command() {
        let cli = Cli::parse_from(["certboy", "completion", "bash"]);
        match cli.command.unwrap() {
            Commands::Completion { shell } => {
                assert_eq!(shell, "bash");
            }
            _ => panic!("Expected Completion command"),
        }
    }

    #[test]
    fn test_cli_parse_revoke_command() {
        let cli = Cli::parse_from([
            "certboy",
            "revoke",
            "abc.example.io",
            "abc2.example.io",
            "--yes",
        ]);
        match cli.command.unwrap() {
            Commands::Revoke { domains, yes, .. } => {
                assert_eq!(domains, vec!["abc.example.io", "abc2.example.io"]);
                assert!(yes);
            }
            _ => panic!("Expected Revoke command"),
        }
    }

    #[test]
    fn test_cli_parse_with_context() {
        let cli = Cli::parse_from([
            "certboy",
            "--context",
            "/custom/context",
            "--domain",
            "test.com",
            "--root-ca",
        ]);
        assert_eq!(cli.context, Some(PathBuf::from("/custom/context")));
    }

    #[test]
    fn test_cli_parse_with_force() {
        let cli = Cli::parse_from([
            "certboy", "--ca", "root.com", "--domain", "test.com", "--force",
        ]);
        assert!(cli.force);
    }

    #[test]
    fn test_cli_parse_with_expiration() {
        let cli = Cli::parse_from([
            "certboy",
            "--domain",
            "test.com",
            "--root-ca",
            "--expiration",
            "365",
        ]);
        assert_eq!(cli.expiration, Some(365));
    }

    #[test]
    fn test_cli_parse_with_country() {
        let cli = Cli::parse_from([
            "certboy",
            "--domain",
            "test.com",
            "--root-ca",
            "--country",
            "US",
        ]);
        assert_eq!(cli.country, "US");
    }

    #[test]
    fn test_cli_default_country() {
        let cli = Cli::parse_from(["certboy", "--domain", "test.com", "--root-ca"]);
        assert_eq!(cli.country, "CN");
    }

    #[test]
    fn test_cli_parse_verbose_levels() {
        let cli1 = Cli::parse_from(["certboy", "-v", "--domain", "test.com", "--root-ca"]);
        assert_eq!(cli1.verbose, 1);

        let cli2 = Cli::parse_from(["certboy", "-vv", "--domain", "test.com", "--root-ca"]);
        assert_eq!(cli2.verbose, 2);

        let cli3 = Cli::parse_from(["certboy", "-vvv", "--domain", "test.com", "--root-ca"]);
        assert_eq!(cli3.verbose, 3);
    }

    #[test]
    fn test_cli_parse_check_with_auto_fix() {
        let cli = Cli::parse_from(["certboy", "check", "--auto-fix"]);
        match cli.command.unwrap() {
            Commands::Check { auto_fix, .. } => {
                assert!(auto_fix);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_parse_import_with_context() {
        let cli = Cli::parse_from([
            "certboy",
            "import",
            "/path/to/ca",
            "--context",
            "/custom/context",
        ]);
        match cli.command.unwrap() {
            Commands::Import {
                context, source, ..
            } => {
                assert_eq!(context, Some(PathBuf::from("/custom/context")));
                assert_eq!(source.len(), 1);
            }
            _ => panic!("Expected Import command"),
        }
    }

    #[test]
    fn test_cli_parse_revoke_without_yes() {
        let cli = Cli::parse_from(["certboy", "revoke", "example.com"]);
        match cli.command.unwrap() {
            Commands::Revoke { domains, yes, .. } => {
                assert_eq!(domains, vec!["example.com"]);
                assert!(!yes);
            }
            _ => panic!("Expected Revoke command"),
        }
    }

    #[test]
    fn test_cli_parse_revoke_with_context() {
        let cli = Cli::parse_from([
            "certboy",
            "revoke",
            "example.com",
            "--context",
            "/custom/path",
            "--yes",
        ]);
        match cli.command.unwrap() {
            Commands::Revoke {
                domains,
                context,
                yes,
            } => {
                assert_eq!(domains, vec!["example.com"]);
                assert_eq!(context, Some(PathBuf::from("/custom/path")));
                assert!(yes);
            }
            _ => panic!("Expected Revoke command"),
        }
    }

    #[test]
    fn test_cli_parse_long_options() {
        let cli = Cli::parse_from(["certboy", "--domain", "test.com", "--root-ca", "--verbose"]);
        assert_eq!(cli.verbose, 1);
    }

    #[test]
    fn test_cli_parse_check_with_detail_and_auto_fix() {
        let cli = Cli::parse_from(["certboy", "check", "--detail", "--auto-fix"]);
        match cli.command.unwrap() {
            Commands::Check {
                detail, auto_fix, ..
            } => {
                assert!(detail);
                assert!(auto_fix);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_parse_export_with_context() {
        let cli = Cli::parse_from([
            "certboy",
            "export",
            "www.example.com",
            "--context",
            "/custom/context",
        ]);
        match cli.command.unwrap() {
            Commands::Export { domain, context } => {
                assert_eq!(domain, "www.example.com");
                assert_eq!(context, Some(PathBuf::from("/custom/context")));
            }
            _ => panic!("Expected Export command"),
        }
    }

    #[test]
    fn test_cli_parse_completion_zsh() {
        let cli = Cli::parse_from(["certboy", "completion", "zsh"]);
        match cli.command.unwrap() {
            Commands::Completion { shell } => {
                assert_eq!(shell, "zsh");
            }
            _ => panic!("Expected Completion command"),
        }
    }

    #[test]
    fn test_cli_parse_completion_fish() {
        let cli = Cli::parse_from(["certboy", "completion", "fish"]);
        match cli.command.unwrap() {
            Commands::Completion { shell } => {
                assert_eq!(shell, "fish");
            }
            _ => panic!("Expected Completion command"),
        }
    }

    #[test]
    fn test_cli_parse_completion_powershell() {
        let cli = Cli::parse_from(["certboy", "completion", "powershell"]);
        match cli.command.unwrap() {
            Commands::Completion { shell } => {
                assert_eq!(shell, "powershell");
            }
            _ => panic!("Expected Completion command"),
        }
    }

    #[test]
    fn test_cli_parse_check_default() {
        let cli = Cli::parse_from(["certboy", "check"]);
        match cli.command.unwrap() {
            Commands::Check {
                renew,
                expiration_alert,
                detail,
                auto_fix,
                yes,
                ..
            } => {
                assert!(!renew);
                assert_eq!(expiration_alert, 14);
                assert!(!detail);
                assert!(!auto_fix);
                assert!(!yes);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_parse_multiple_domains_with_ica() {
        let cli = Cli::parse_from([
            "certboy",
            "--ca",
            "root.com",
            "--domain",
            "www.example.com",
            "--domain",
            "api.example.com",
            "--domain",
            "127.0.0.1",
            "--cn",
            "Test ICA",
        ]);
        assert_eq!(cli.ca, Some("root.com".to_string()));
        assert_eq!(cli.domain.len(), 3);
        assert_eq!(cli.cn, Some("Test ICA".to_string()));
    }

    #[test]
    fn test_cli_parse_ica_mode_with_expiration() {
        let cli = Cli::parse_from([
            "certboy",
            "--ca",
            "root.com",
            "--domain",
            "ica.example.com",
            "--cn",
            "Test ICA",
            "--expiration",
            "1825",
        ]);
        assert_eq!(cli.ca, Some("root.com".to_string()));
        assert_eq!(cli.expiration, Some(1825));
        assert!(cli.cn.is_some());
    }

    #[test]
    fn test_cli_parse_cert_mode_without_cn() {
        let cli = Cli::parse_from(["certboy", "--ca", "root.com", "--domain", "www.example.com"]);
        assert_eq!(cli.ca, Some("root.com".to_string()));
        assert!(cli.cn.is_none());
        assert!(!cli.root_ca);
    }

    #[test]
    fn test_cli_parse_check_without_context() {
        let cli = Cli::parse_from(["certboy", "check", "--renew"]);
        match cli.command.unwrap() {
            Commands::Check { context, .. } => {
                assert!(context.is_none());
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_parse_import_multiple_paths() {
        let cli = Cli::parse_from([
            "certboy",
            "import",
            "/path/to/ca1",
            "/path/to/ca2",
            "/path/to/ca3",
        ]);
        match cli.command.unwrap() {
            Commands::Import { source, .. } => {
                assert_eq!(source.len(), 3);
                assert_eq!(source[0], PathBuf::from("/path/to/ca1"));
                assert_eq!(source[1], PathBuf::from("/path/to/ca2"));
                assert_eq!(source[2], PathBuf::from("/path/to/ca3"));
            }
            _ => panic!("Expected Import command"),
        }
    }

    #[test]
    fn test_cli_parse_revoke_multiple_domains() {
        let cli = Cli::parse_from([
            "certboy",
            "revoke",
            "domain1.com",
            "domain2.com",
            "domain3.com",
        ]);
        match cli.command.unwrap() {
            Commands::Revoke { domains, yes, .. } => {
                assert_eq!(domains.len(), 3);
                assert_eq!(domains[0], "domain1.com");
                assert_eq!(domains[1], "domain2.com");
                assert_eq!(domains[2], "domain3.com");
                assert!(!yes);
            }
            _ => panic!("Expected Revoke command"),
        }
    }

    struct EnvGuard {
        key: String,
        original_value: Option<String>,
    }

    impl EnvGuard {
        fn new(key: &str, value: &str) -> Self {
            let original_value = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                original_value,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original_value {
                Some(val) => std::env::set_var(&self.key, val),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
