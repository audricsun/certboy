---
layout: default
title: Check Command
---

# Check Command

The `check` command inspects certificates in the context, validates their structure, and reports issues.

## Basic Usage

```bash
certboy check
```

## Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--renew` | `-r` | Renew certificates needing renewal | false |
| `--expiration-alert` | `-E` | Days threshold for expiration warning | 14 |
| `--detail` | | Show detailed info including DNS names and IPs | false |
| `--auto-fix` | | Automatically fix detected issues | false |
| `--yes` | `-y` | Skip confirmation prompts | false |
| `--verify-openssl` | | Verify private key matches certificate | false |
| `--remote` | `-R` | Check remote TLS cert against local | false |
| `--context` | `-C` | Context path | `~/.local/state/certboy` |

## Examples

### Basic Check

```bash
certboy check
```

### Detailed Output

Shows all certificate details including SANs:

```bash
certboy check --detail
```

### Renewal Mode

Renew certificates within the alert threshold:

```bash
certboy check --renew
```

### Auto-fix Mode

Automatically fix structural issues:

```bash
certboy check --auto-fix
certboy check --auto-fix --yes  # Non-interactive
```

### OpenSSL Verification

Verify key/cert matching for TLS certificates:

```bash
certboy check --verify-openssl
```

### Remote Certificate Check

Compare remote TLS certificate with local:

```bash
certboy check --remote
```

This performs:
1. DNS resolution check with resolved IPs
2. TCP connect to port 443
3. SSL handshake and cert fetch
4. Serial comparison with local certificate

### Custom Expiration Threshold

```bash
certboy check --expiration-alert 30
```

## What Gets Checked

- Certificate expiration status
- Certificate chain validity
- Private key/certificate matching
- Serial number issues
- Fullchain ordering
- Remote certificate verification (with `--remote`)