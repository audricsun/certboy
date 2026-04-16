---
layout: default
title: Revoke Certificates
---

# Revoke Certificates

The `revoke` command removes certificates from the context. This operation is **irreversible**.

## Revoke a TLS Certificate

```bash
certboy revoke www.example.com
```

## Revoke Multiple Certificates

```bash
certboy revoke www.example.com api.example.com
```

## Revoke an ICA

When revoking an ICA, all TLS certificates signed by that ICA are affected:

```bash
certboy revoke ops.example.com
```

You will be prompted to confirm, showing which certificates will be impacted.

### Skip Confirmation

```bash
certboy revoke ops.example.com --yes
```

## Revocation Behavior

| Type | What Gets Removed |
|------|-------------------|
| TLS Certificate | The certificate directory |
| Intermediate CA | The ICA and all its signed certificates |
| Root CA | The entire Root CA directory (including all ICAs and certificates) |

## Safety

This operation is **permanent**. Certificates will be **permanently deleted** from the context.

Always export certificates before revoking if you may need them later:

```bash
# Export first
certboy export www.example.com

# Then revoke
certboy revoke www.example.com
```

## Examples

### Revoke with Confirmation

```bash
certboy revoke www.example.com
# Prompts: "Are you sure you want to revoke www.example.com? [y/N]"
```

### Non-interactive Revoke

```bash
certboy revoke www.example.com --yes
```

### Revoke with Custom Context

```bash
certboy revoke www.example.com --context /path/to/context
```

### Revoke Multiple Different Types

```bash
certboy revoke \
  www.example.com \
  api.example.com \
  ops.example.com \
  --yes
```