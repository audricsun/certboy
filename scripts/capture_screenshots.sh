#!/usr/bin/env bash
# certboy screenshot capture script
# Captures terminal screenshots at 800px width with minimal prompt
#
# Requirements:
#   - X11 (Xorg or Xvfb)
#   - gnome-terminal (or xterm as fallback)
#   - ImageMagick (import command)
#   - xdotool
#
# Install on Ubuntu/Debian:
#   apt-get install xvfb imagemagick xdotool gnome-terminal
#
# Install on macOS (with XQuartz):
#   brew install imagemagick xdotool
#   # Use XQuartz for X11 support

set -euo pipefail

BIN="/home/szhou/workspace/github.com/private/certboy/target/release/certboy"
OUTPUT="/home/szhou/workspace/github.com/private/certboy/docs/images"

# Ensure output dir exists
mkdir -p "$OUTPUT"

# Start a headless X server if DISPLAY is not set or invalid
start_xvfb() {
    if [ -z "${DISPLAY:-}" ] || ! xdpyinfo >/dev/null 2>&1; then
        echo "Starting Xvfb on :99 (1024x768x24)..."
        Xvfb :99 -screen 0 1024x768x24 &
        export DISPLAY=:99
        sleep 2
    fi
    echo "Using DISPLAY=$DISPLAY"
}

# Install dependencies if missing
check_deps() {
    local missing=()
    for cmd in Xvfb gnome-terminal import xdotool; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        echo "ERROR: Missing dependencies: ${missing[*]}"
        echo "Install with: apt-get install ${missing[*]}"
        exit 1
    fi
}

# Capture a terminal window at 800px width
capture() {
    local title="$1"
    local cmd="$2"
    local out="$OUTPUT/${title}.png"

    echo "Capturing: $title"

    # Launch gnome-terminal with 800px width
    gnome-terminal --title="$title" --geometry=100x25+0+0 --hide-menubar -- bash -lc "
        export PS1='\$ '
        export TERM=xterm-256color
        printf '\$ %s\n' \"$cmd\"
        $cmd
        printf '\n'
        read -n1 -s -r -p 'Press any key to close'
    " &

    local pid=$!
    sleep 1

    # Find and capture the window
    local win_id=""
    for i in {1..10}; do
        win_id=$(xdotool search --name "$title" 2>/dev/null | head -n 1 || true)
        if [ -n "$win_id" ]; then
            break
        fi
        sleep 0.3
    done

    if [ -n "$win_id" ]; then
        # Capture at window size (should be ~800px wide)
        import -window "$win_id" "$out"
        echo "  -> Saved: $out ($(identify -format '%wx%h' "$out"))"
    else
        echo "  -> WARNING: Could not capture window '$title'"
    fi

    # Kill the terminal
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true

    # Close any orphaned terminals
    pkill -f "gnome-terminal.*title=$title" 2>/dev/null || true
}

# Main
check_deps
start_xvfb

# Set minimal prompt for all terminals
export PS1='$ '

echo ""
echo "=== certboy Screenshot Capture ==="
echo "Output: $OUTPUT"
echo "Terminal width: 800px"
echo ""

# Capture all screenshots
capture "01-help" "$BIN --help"
capture "02-check-help" "$BIN check --help"
capture "03-import-help" "$BIN import --help"
capture "04-export-help" "$BIN export --help"
capture "05-completion-help" "$BIN completion --help"
capture "06-revoke-help" "$BIN revoke --help"
capture "08-root-ca-cn-org" "$BIN --context /tmp/certboy-screenshots --domain example.com --cn 'Example Organization' --root-ca"
capture "09-ica-cn-org2" "$BIN --context /tmp/certboy-screenshots --ca example.com --domain ops.example.com --cn 'Ops Division'"
capture "10-tls-multi-sans" "$BIN --context /tmp/certboy-screenshots --ca example.com -d multi.example.io -d '*.multi.example.io' -d api.multi.example.io -d 10.0.0.1"

echo ""
echo "=== Capture Complete ==="
echo "Screenshots saved to: $OUTPUT"
echo ""
echo "Note: Run quickstart.sh first before capturing check-detail:"
echo "  ./scripts/quickstart.sh"
echo "  Then re-run: capture_screenshots.sh"
echo ""
echo "To capture 07-check-detail separately after quickstart:"
capture "07-check-detail" "$BIN --context /tmp/certboy-screenshots check --detail"

echo ""
ls -la "$OUTPUT"/*.png 2>/dev/null || echo "No PNGs found"