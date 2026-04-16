---
layout: default
title: Intermediate CA
---

# Intermediate CA (ICA)

An Intermediate CA is a certificate issued by a Root CA, used for delegated certificate signing. This allows you to have multiple signing authorities with different trust policies.

## Create an Intermediate CA

```bash
certboy --domain ops.example.com --ca example.com --cn "Ops Division"
```

**Parameters:**

| Flag | Description | Required |
|------|-------------|----------|
| `--domain` | The domain for the ICA | Yes |
| `--ca` | Parent CA (Root CA or ICA) name | Yes |
| `--cn` | Common Name for the ICA | Yes |
| `--country` | Country code (default: CN) | No |
| `--expiration` | Expiration in days (default: 3650/10 years) | No |

## Domain Ownership Validation

An ICA can only sign certificates within its domain subtree. This is a security feature.

**Example:**

- ICA: `ops.example.com`
- **Allowed:** `ops.example.com`, `grafana.ops.example.com`, `a.b.ops.example.com`
- **Not allowed:** `example.com`, `dev.example.com`, `other.com`

## Examples

### Basic ICA

```bash
certboy --domain ops.example.com --ca example.com --cn "Ops Division"
```

### ICA with Custom Expiration

```bash
# 5 years
certboy --domain services.example.com --ca example.com --cn "Services" --expiration 1825
```

### Nested ICA (ICA signing ICA)

```bash
# Create a second-level ICA
certboy --domain team.ops.example.com --ca ops.example.com --cn "Team Services"
```

## Context Structure

After creating an ICA, the directory structure under the parent CA:

```
example.com/
├── meta.json
├── crt.pem
├── key.pem
├── intermediates.d/
│   └── ops.example.com/
│       ├── meta.json
│       ├── crt.pem
│       ├── key.pem
│       └── certs.d/
│           └── www.example.com/
└── certs.d/
    └── www.example.com/
```