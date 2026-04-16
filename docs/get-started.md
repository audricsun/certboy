---
layout: default
title: Get Started
---

# Get Started

Certboy is a unified certificate management tool that simplifies creating and managing a local PKI hierarchy: Root CA → Intermediate CA → TLS certificates.

## Installation

### Install from Release (Binary)

Download the latest release from [GitHub Releases](https://github.com/audricsun/certboy/releases).

**Linux/macOS:**

```bash
# Download the latest release for your platform
curl -L https://github.com/audricsun/certboy/releases/download/v2026.16.15/certboy-x86_64-unknown-linux-musl.tar.gz | tar xz

# Make executable and move to PATH
chmod +x certboy
sudo mv certboy /usr/local/bin/
```

**macOS (Apple Silicon):**

```bash
curl -L https://github.com/audricsun/certboy/releases/download/v2026.16.15/certboy-aarch64-apple-darwin.tar.gz | tar xz
chmod +x certboy
sudo mv certboy /usr/local/bin/
```

### Install with Cargo

If you have Rust installed, you can build from source:

```bash
cargo install certboy
```

Or build from source manually:

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

### 1. Initialize a Root CA

Create your trust anchor - a self-signed Root CA:

```bash
certboy --domain example.com --cn "Example Organization" --root-ca
```

### 2. Create an Intermediate CA (Optional)

For larger deployments, create an Intermediate CA signed by your Root CA:

```bash
certboy --domain ops.example.com --ca example.com --cn "Ops Division"
```

### 3. Issue TLS Certificates

Issue a TLS certificate for your server:

```bash
# Single domain
certboy --ca example.com -d www.example.com

# Multiple SANs (Subject Alternative Names)
certboy --ca example.com --domain api.example.com --domain '*.example.com' --domain 192.168.1.100
```

### 4. Check Certificates

Monitor certificate status:

```bash
certboy check
certboy check --detail
```

## Common Workflows

### Certificate Renewal

```bash
# Check for expiring certificates
certboy check --renew

# With custom alert threshold (30 days)
certboy check --expiration-alert 30 --renew
```

### Export Certificates

Export certificates for use with web servers:

```bash
certboy export www.example.com
# Outputs: www.example.com.crt and www.example.com.key
```

### Import Existing CA

Import an existing CA structure:

```bash
certboy import /path/to/ca-folder --context /path/to/context
```

## Next Steps

- [User Guides]({% link user-guides/index.md %}) - Detailed guides for all features
- [CLI Reference]({% link reference/index.md %}) - Complete command reference
- [GitHub Repository](https://github.com/audricsun/certboy) - Report issues and contribute