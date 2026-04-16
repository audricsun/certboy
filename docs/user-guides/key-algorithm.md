---
layout: default
title: Key Algorithm
---

# Key Algorithm

Certboy supports two key algorithms for generating CA and certificate keys: **ECDSA** and **RSA**.

## Algorithm Options

| Algorithm | Flag Value | Key Size | Default |
|-----------|------------|----------|---------|
| ECDSA P-256 | `ecdsa` | 256-bit | Yes |
| RSA | `rsa` | 2048-bit+ | No |

## Root CA Algorithm

When creating a Root CA, specify the algorithm:

```bash
# ECDSA (default)
certboy --domain example.com --cn "Example" --root-ca
certboy --domain example.com --cn "Example" --root-ca --key-algorithm ecdsa

# RSA
certboy --domain example.com --cn "Example" --root-ca --key-algorithm rsa
```

## Algorithm Inheritance

When you create a Root CA, its algorithm is stored in `meta.json`. All certificates issued under this Root CA **inherit** the same algorithm:

```
Root CA (ECDSA)
├── ICA (inherits ECDSA)
│   └── Certificate (inherits ECDSA)
└── Certificate (inherits ECDSA)
```

This ensures cryptographic consistency throughout your PKI hierarchy.

## Comparison

| Feature | ECDSA | RSA |
|---------|-------|-----|
| Performance | Faster signing | Slower signing |
| Key Size | Smaller (256-bit) | Larger (2048-bit+) |
| Signature Size | Smaller | Larger |
| Browser Support | Universal | Universal |
| Hardware Token Support | Good | Excellent |

## Choosing an Algorithm

**Use ECDSA when:**
- Performance matters (faster TLS handshakes)
- You want smaller certificates
- Modern infrastructure is prioritized

**Use RSA when:**
- Maximum compatibility is required
- Hardware token/tokenization support is needed
- Operating with legacy systems