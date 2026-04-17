# Get Started

Certboy is a unified certificate management tool that simplifies creating and managing a local PKI hierarchy: Root CA → Intermediate CA → TLS certificates.

## Installation

### Install from Release (Binary)

Download the latest release from [GitHub Releases](https://github.com/audricsun/certboy/releases).

**One-liner installation (Linux x86_64):**

```bash
VERSION=$(curl -sL https://github.com/audricsun/certboy/releases/download/latest/stable.txt) && \
curl -sL "https://github.com/audricsun/certboy/releases/download/v${VERSION}/certboy-${VERSION}-x86_64-unknown-linux-musl.tar.gz" | tar xz && \
chmod +x certboy && \
sudo mv certboy /usr/local/bin/
```

**One-liner installation (Linux ARM64):**

```bash
VERSION=$(curl -sL https://github.com/audricsun/certboy/releases/download/latest/stable.txt) && \
curl -sL "https://github.com/audricsun/certboy/releases/download/v${VERSION}/certboy-${VERSION}-aarch64-unknown-linux-musl.tar.gz" | tar xz && \
chmod +x certboy && \
sudo mv certboy /usr/local/bin/
```

**One-liner installation (macOS Intel):**

```bash
VERSION=$(curl -sL https://github.com/audricsun/certboy/releases/download/latest/stable.txt) && \
curl -sL "https://github.com/audricsun/certboy/releases/download/v${VERSION}/certboy-${VERSION}-x86_64-apple-darwin.tar.gz" | tar xz && \
chmod +x certboy && \
sudo mv certboy /usr/local/bin/
```

**One-liner installation (macOS Apple Silicon):**

```bash
VERSION=$(curl -sL https://github.com/audricsun/certboy/releases/download/latest/stable.txt) && \
curl -sL "https://github.com/audricsun/certboy/releases/download/v${VERSION}/certboy-${VERSION}-aarch64-apple-darwin.tar.gz" | tar xz && \
chmod +x certboy && \
sudo mv certboy /usr/local/bin/
```

### Install with Cargo

If you have Rust installed:

```bash
cargo install certboy
```

Or build from source:

```bash
git clone https://github.com/audricsun/certboy.git
cd certboy
cargo build --release
sudo cp target/release/certboy /usr/local/bin/
```

### Verify Installation

```bash
certboy --version
```

## Quickstart

The fastest way to get started is to run the quickstart script, which creates a complete sandbox environment with multiple Root CAs, ICAs, and TLS certificates:

```bash
./scripts/quickstart.sh
```

This script demonstrates:

- **Step 1-2**: Creating multiple Root CAs (`example.io`, `sandbox.dev`, `corp.local`)
- **Step 3-6**: Creating Intermediate CAs under each Root CA
- **Step 7-8**: Issuing TLS certificates signed by Root CAs and ICAs
- **Step 8b**: Creating certificates with multiple domains and wildcards
- **Step 9**: Checking all certificates
- **Step 10**: Testing expiration alerts and renewal
- **Step 11**: Testing import functionality
- **Step 12-14**: Verifying certificate chains with OpenSSL
- **Step 15**: Final verification of all certificates
- **Step 16**: Testing export functionality

After running the script, explore the `sandbox/` directory to see the complete PKI structure.

## Next Steps

- [User Guides](user-guides/index.md) - Detailed guides for all features
- [CLI Reference](user-guides/reference.md) - Complete command reference
- [GitHub Repository](https://github.com/audricsun/certboy) - Report issues and contribute