#!/usr/bin/env python3
import subprocess
import os

BIN = "/home/szhou/workspace/github.com/private/certboy/target/release/certboy"
OUTPUT = "/home/szhou/workspace/github.com/private/certboy/docs/images"
WIDTH = 800
CTX = "/tmp/certboy-screenshots"

def run_cmd(cmd):
    env = os.environ.copy()
    env["CERTBOY_CONTEXT"] = CTX
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)
    return result.stdout + result.stderr

def create_screenshot(title, cmd):
    out = os.path.join(OUTPUT, f"{title}.png")
    print(f"Capturing: {title}")

    output = run_cmd(cmd)
    caption = "$ " + cmd + "\n" + output

    p = subprocess.run([
        "convert",
        "-size", f"{WIDTH}",
        "-background", "#1e1e1e",
        "-fill", "#d4d4d4",
        "-font", "Courier",
        "-pointsize", "13",
        f"caption:{caption}",
        out
    ], capture_output=True, text=True)

    if p.returncode != 0:
        print(f"  Error: {p.stderr[:200]}")
        return

    result = subprocess.run(["identify", "-format", "%wx%h", out], capture_output=True, text=True)
    print(f"  -> {out} ({result.stdout.strip()})")

def main():
    os.makedirs(OUTPUT, exist_ok=True)
    os.environ["CERTBOY_CONTEXT"] = os.path.join(OUTPUT, "../.certboy_context")
    os.makedirs(os.environ["CERTBOY_CONTEXT"], exist_ok=True)

    print("=== certboy Screenshot Capture ===")
    print(f"Output: {OUTPUT}, Width: {WIDTH}px")
    print()

    os.environ["CERTBOY_CONTEXT"] = "/tmp/certboy-screenshots"

    commands = [
        ("01-help", f"{BIN} --help"),
        ("02-check-help", f"{BIN} check --help"),
        ("03-import-help", f"{BIN} import --help"),
        ("04-export-help", f"{BIN} export --help"),
        ("05-completion-help", f"{BIN} completion --help"),
        ("06-revoke-help", f"{BIN} revoke --help"),
        ("08-root-ca-cn-org", f"{BIN} --domain example.com --cn 'Example Organization' --root-ca"),
        ("09-ica-cn-org2", f"{BIN} --domain ops.example.com --ca example.com --cn 'Ops Division'"),
        ("10-tls-multi-sans", f"{BIN} --ca example.com -d multi.example.io -d '*.multi.example.io' -d api.multi.example.io -d 10.0.0.1"),
        ("check-detail", f"{BIN} check --detail"),
    ]

    for title, cmd in commands:
        try:
            create_screenshot(title, cmd)
        except Exception as e:
            print(f"  Error: {e}")

if __name__ == "__main__":
    main()