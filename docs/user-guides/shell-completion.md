---
layout: default
title: Shell Completion
---

# Shell Completion

Certboy can generate shell completion scripts for bash, zsh, fish, and PowerShell.

## Generate Completion

```bash
certboy completion bash
certboy completion zsh
certboy completion fish
certboy completion powershell
```

## Bash

### System-wide Installation

```bash
sudo certboy completion bash > /etc/bash_completion.d/certboy
```

### User-specific Installation

```bash
mkdir -p ~/.local/share/certboy/completions
certboy completion bash > ~/.local/share/certboy/completions/certboy
```

Add to `~/.bashrc`:

```bash
source ~/.local/share/certboy/completions/certboy
```

## Zsh

```bash
certboy completion zsh > ~/.zsh/completions/_certboy
```

Add to `~/.zshrc`:

```bash
fpath=(~/.zsh/completions $fpath) && autoload -Uz compinit && compinit
```

## Fish

```bash
certboy completion fish > ~/.config/fish/completions/certboy.fish
```

Completion works automatically on next shell start.

## PowerShell

```bash
certboy completion powershell >> $PROFILE
```

Or save to a file:

```bash
certboy completion powershell > certboy.ps1
. ./certboy.ps1
```

## Verified Shells

Completion has been tested with:

- **Bash** 5.x
- **Zsh** 5.x
- **Fish** 3.x
- **PowerShell** 5.x+