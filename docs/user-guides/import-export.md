---
layout: default
title: Import and Export
---

# Import and Export

Certboy provides import and export functionality to work with certificates outside the default context.

## Export

Export a TLS certificate and key to the current directory.

### Basic Export

```bash
certboy export www.example.com
```

This creates:
- `www.example.com.crt` - Public certificate
- `www.example.com.key` - Private key

### Export with Custom Context

```bash
certboy export www.example.com --context /path/to/context
```

## Import

Import an existing Root CA or ICA folder into a new context.

### Basic Import

```bash
certboy import /path/to/ca-folder --context /path/to/new-context
```

### Import Multiple CAs

```bash
certboy import /path/to/ca1 /path/to/ca2 --context /path/to/context
```

### Import Requirements

The source folder must contain:
- `crt.pem` - Public certificate

### Examples

#### Import a Root CA

```bash
certboy import /path/to/root-ca-example.com --context ~/.local/state/certboy
```

#### Import an ICA

```bash
certboy import /path/to/ica.ops.example.com --context ~/.local/state/certboy
```

#### Import Multiple

```bash
certboy import \
  /path/to/root-ca1.com \
  /path/to/root-ca2.com \
  --context /path/to/consolidated-context
```

## Use Cases

### Backup and Restore

Export certificates for backup, import to restore:

```bash
# Export
certboy export www.example.com --context /backup/context

# Import to new location
certboy import /backup/context/example.com --context /new/context
```

### Migration

Move certificates between systems:

```bash
# On old system
certboy export www.example.com

# Copy files to new system, then import
certboy import /path/to/www.example.com --context /new/context
```

### Consolidation

Combine multiple CA hierarchies:

```bash
certboy import /path/to/ca-a --context /consolidated
certboy import /path/to/ca-b --context /consolidated
```