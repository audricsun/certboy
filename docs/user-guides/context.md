---
layout: default
title: Context
---

# Context

A **context** is a directory that stores all certificate authorities and TLS certificates managed by certboy.

## Default Context

```
~/.local/state/certboy/
```

This location is used when:
- No `--context` flag is provided
- No `CERTBOY_CONTEXT` environment variable is set

## Override Context

### Command-line Flag

```bash
certboy --context /path/to/context check
certboy --context /path/to/context --domain example.com --root-ca
```

### Environment Variable

```bash
export CERTBOY_CONTEXT=/path/to/context
certboy check
```

## Directory Structure

A context contains Root CA directories:

```
~/.local/state/certboy/
├── example.com/              # Root CA
│   ├── meta.json
│   ├── crt.pem
│   ├── key.pem
│   ├── intermediates.d/     # Intermediate CAs
│   │   └── ops.example.com/
│   └── certs.d/             # TLS certificates
│       └── www.example.com/
└── another.com/             # Another Root CA
    └── ...
```

## Creating Contexts

The context is created automatically when you create your first Root CA:

```bash
certboy --domain example.com --cn "Example" --root-ca
# Creates: ~/.local/state/certboy/example.com/
```

Or explicitly before importing:

```bash
certboy import /path/to/ca --context /new/context
```

## Use Cases

### Separate Environments

```bash
# Production certificates
certboy --context ~/.local/state/certboy-prod ...

# Development certificates
certboy --context ~/.local/state/certboy-dev ...
```

### Project-specific

```bash
certboy --context ./certs --domain example.com --root-ca
```

## XDG Base Directory

Certboy follows the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html):

- Default: `~/.local/state/certboy`
- Override: `$XDG_STATE_HOME/certboy` (if set)