---
layout: default
title: Certificate Renewal
---

# Certificate Renewal

Certboy provides tools to check certificate expiration and renew certificates that are nearing expiration.

## Check Certificates

```bash
certboy check
```

### Check with Details

Show detailed information including DNS names and IP addresses:

```bash
certboy check --detail
```

### Expiration Alert Threshold

By default, certificates expiring within 14 days are flagged. Customize:

```bash
# 30 day threshold
certboy check --expiration-alert 30
```

## Renew Expiring Certificates

```bash
certboy check --renew
```

This will renew certificates that are:
- Within the expiration alert threshold
- Not yet expired

### Dry Run

Combine `--renew` with `--yes` to see what would be renewed without prompting:

```bash
certboy check --renew --yes
```

## Auto-fix

The `--auto-fix` flag detects and fixes common certificate issues:

- Wrong `fullchain.crt` order (ICA-signed certificates)
- Duplicate or zero serial numbers
- Certificates needing re-signing due to structural issues

```bash
# Interactive mode (prompts before each fix)
certboy check --auto-fix

# Automatic mode (applies fixes without prompting)
certboy check --auto-fix --yes
```

## Combining Options

You can combine `--renew` and `--auto-fix`:

```bash
certboy check --renew --auto-fix
```

- `--renew` restricts the set to expiring certificates
- `--auto-fix` controls whether fixes are offered/applied

## Verify Certificate Key Match

Verify that the private key matches the certificate using OpenSSL:

```bash
certboy check --verify-openssl
```

This is useful for TLS certificates to ensure the key/cert pair is valid.