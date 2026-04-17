#!/usr/bin/env bash
set -euo pipefail

BIN="/home/szhou/workspace/github.com/private/certboy/target/release/certboy"
OUTPUT="/home/szhou/workspace/github.com/private/certboy/docs/images"
WIDTH=800

mkdir -p "$OUTPUT"

render() {
    local title="$1"
    local cmd="$2"
    local out="$OUTPUT/${title}.png"

    echo "Capturing: $title"

    local output
    output=$(eval "$cmd" 2>&1) || true

    local text="\$ $cmd"$'\n'"$output"

    convert -size ${WIDTH} -background "#1e1e1e" -fill "#d4d4d4" -font Courier -pointsize 13 \
        label:"$text" "$out"

    echo "  -> $out ($(identify -format '%wx%h' "$out"))"
}

export CERTBOY_CONTEXT="${OUTPUT}/../.certboy_context"
mkdir -p "$CERTBOY_CONTEXT"

echo "=== certboy Screenshot Capture ==="
echo "Output: $OUTPUT, Width: ${WIDTH}px"
echo ""

render "01-help" "$BIN --help"
render "02-check-help" "$BIN check --help"
render "03-import-help" "$BIN import --help"
render "04-export-help" "$BIN export --help"
render "05-completion-help" "$BIN completion --help"
render "06-revoke-help" "$BIN revoke --help"

echo ""
ls -la "$OUTPUT"/*.png 2>/dev/null