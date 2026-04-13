# certboy Guide

This document explains how to use certboy to manage a local PKI (Root CA → Intermediate CA → TLS certificates).

## Concepts

### Certificate Types

- Root CA: trust anchor, self-signed
- Intermediate CA (ICA): issued by a Root CA, used for delegated signing
- TLS/server certificate: issued by a Root CA or an ICA

### Context

A context is a single directory that stores Root CAs, ICAs, and TLS certificates.

- Default: `~/.local/state/certboy` (or `$XDG_STATE_HOME/certboy`)
- Override: `--context <path>`
- Env override: `CERTBOY_CONTEXT`
- Legacy env fallbacks: `CERTM_CONTEXT`, `BW_MKCERT_CONTEXT`

## Key Algorithm Inheritance

When you create a Root CA, you choose a key algorithm:

- Default: `ecdsa` (ECDSA P-256)
- Optional: `rsa`

The selected algorithm is written to `meta.json` and all ICAs/TLS certificates under that Root CA inherit the same algorithm.

Examples:

```bash
certboy --domain example.com --cn ExampleOrg --root-ca
certboy --domain example.com --cn ExampleOrg --root-ca --key-algorithm rsa
```

## Create a Root CA

```bash
certboy --domain example.io --cn "Example Organization" --root-ca
```

## Create an Intermediate CA

```bash
certboy --domain ops.example.io --ca example.io --cn "Ops Division"
```

## Issue TLS Certificates

Single domain:

```bash
certboy --ca example.io -d www.example.io
```

Multiple SANs:

```bash
certboy --ca ops.example.io \
  --domain api.example.com \
  --domain '*.example.com' \
  --domain 192.168.1.100
```

Positional domain/SAN arguments are also supported (merged with `-d/--domain`):

```bash
certboy --ca ops.example.io api.example.com '*.example.com' 192.168.1.100
```

## ICA Domain Ownership Validation

An ICA can only sign certificates within its domain subtree.

Example:

- ICA: `ops.example.io`
- Allowed: `ops.example.io`, `grafana.ops.example.io`, `a.b.ops.example.io`
- Not allowed: `example.io`, `dev.example.io`, `other.com`

## Check and Renew

List certificates in a context:

```bash
certboy check
```

Show details (including SANs for TLS certificates):

```bash
certboy check --detail
```

Renew certificates that are expiring (within the alert threshold):

```bash
certboy check --renew
certboy check --expiration-alert 30 --renew
```

### Auto-fix (and `--yes`)

`check --auto-fix` detects common structural issues and offers to fix them. By default, it prompts before each fix (default answer is `No`).

```bash
certboy check --auto-fix
```

Use `--yes` to skip confirmations (use with care):

```bash
certboy check --auto-fix --yes
```

Auto-fix can address:

- TLS certificates: wrong `fullchain.crt` order (ICA-signed certs)
- TLS certificates: re-sign with a new serial when serial is `0`, duplicate, or renewal is needed
- ICAs: re-sign ICA and affected children when issues are detected

You can combine `--renew` and `--auto-fix`. `--renew` restricts the set to expiring certificates (within the alert threshold), while `--auto-fix` controls whether fixes are offered/applied.

Verify key/cert match using OpenSSL (TLS certificates only):

```bash
certboy check --verify-openssl
```

## Import

Import an existing Root CA folder (or ICA folder) into a context:

```bash
certboy import /path/to/root-ca-folder --context /opt/my-certs
certboy import /path/to/root-ca-folder/intermediates.d/ops.example.io --context /opt/my-certs
```

## Export

Export a TLS certificate and key into the current directory:

```bash
certboy export www.example.com
certboy export www.example.com --context /path/to/certs
```

## Revoke

Revoke removes certificates from the context:

```bash
certboy revoke www.example.com
certboy revoke www.example.com api.example.com
certboy revoke ica.example.com --yes
```

This operation is irreversible.
