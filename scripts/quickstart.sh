#!/bin/bash
set -e

# certboy Quickstart Script
# Creates a sandbox environment with multiple Root CAs, ICAs, and TLS certificates

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SANDBOX_DIR="$PROJECT_DIR/sandbox"

echo "=== certboy Quickstart ==="
echo ""

# Clean up any existing sandbox
if [ -d "$SANDBOX_DIR" ]; then
    echo "Cleaning up existing sandbox..."
    rm -rf "$SANDBOX_DIR"
fi

echo "Creating sandbox directory: $SANDBOX_DIR"
mkdir -p "$SANDBOX_DIR"

cd "$PROJECT_DIR"

# Step 1: Create Root CA - example.io
echo ""
echo "=== Step 1: Create Root CA 'example.io' ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --domain example.io \
    --cn "Example Organization" \
    --root-ca

# Step 2: Create Root CA - sandbox.dev
echo ""
echo "=== Step 2: Create Root CA 'sandbox.dev' ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --domain sandbox.dev \
    --cn "Sandbox Development" \
    --root-ca

# Step 3: Create ICAs for example.io
echo ""
echo "=== Step 3: Create ICAs for example.io ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca example.io \
    --domain ops.example.io \
    --cn "Ops Division"

cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca example.io \
    --domain dev.example.io \
    --cn "Dev Division"

# Step 4: Create ICAs for sandbox.dev
echo ""
echo "=== Step 4: Create ICAs for sandbox.dev' ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca sandbox.dev \
    --domain test.sandbox.dev \
    --cn "Test Division"

# Step 5: Create Root CA with different CN and Organization (CN != Organization)
echo ""
echo "=== Step 5: Create Root CA with different CN and Organization ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --domain corp.local \
    --cn "Corporate Root CA" \
    --root-ca

# Step 6: Create ICA with different CN and Organization
echo ""
echo "=== Step 6: Create ICA with different CN and Organization ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca corp.local \
    --domain engineering.corp.local \
    --cn "Engineering PKI"

# Step 7: Create TLS certs signed by Root CA (example.io)
echo ""
echo "=== Step 7: Create TLS certs signed by Root CA ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca example.io \
    --domain www.example.io

cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca example.io \
    --domain api.example.io

# Step 8: Create TLS certs signed by ICAs
echo ""
echo "=== Step 8: Create TLS certs signed by ICAs ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca ops.example.io \
    --domain dashboard.ops.example.io

cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca dev.example.io \
    --domain jenkins.dev.example.io

cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca test.sandbox.dev \
    --domain local.test.sandbox.dev

# Step 8b: Create TLS certs with multiple domains and wildcard
echo ""
echo "=== Step 8b: Create TLS certs with Multiple Domains and Wildcard ==="
cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca example.io \
    --domain multi.example.io \
    --domain '*.multi.example.io' \
    --domain api.multi.example.io \
    --domain 10.0.0.1

echo ""
echo "--- Certificate details for multi.example.io ---"
echo "Subject Alternative Names:"
openssl x509 -in "$SANDBOX_DIR/example.io/certificates.d/multi.example.io/crt.pem" -noout -text | grep -A 10 "Subject Alternative Name"

# Step 9: Check all certificates
echo ""
echo "=== Step 9: Certificate Check ==="
cargo run -- check --context "$SANDBOX_DIR"

# Step 10: Test Expiration Alert and Renewal
echo ""
echo "=== Step 10: Test Expiration Alert and Renewal ==="
echo "--- Create certificate with 7-day expiration ---"
cargo run -- \
    --context "$SANDBOX_DIR" \
    --ca example.io \
    --domain shortlived.example.io \
    --expiration 7

echo ""
echo "--- Check certificates with expiration alert (default 14 days) ---"
cargo run -- check --context "$SANDBOX_DIR"

echo ""
echo "--- Check certificates with custom expiration alert (5 days) ---"
cargo run -- check --context "$SANDBOX_DIR" --expiration-alert 5

echo ""
echo "--- Renew certificates that need renewal ---"
cargo run -- check --context "$SANDBOX_DIR" --renew

# Step 11: Test Import functionality
echo ""
echo "=== Step 11: Test Import Functionality ==="
echo "--- Export an ICA with its Root CA for import testing ---"
# Copy the root CA and ica folder to a temp location for import testing
IMPORT_SOURCE_DIR="$PROJECT_DIR/test_import_ica"
rm -rf "$IMPORT_SOURCE_DIR"
mkdir -p "$IMPORT_SOURCE_DIR"
# Copy root CA
cp -r "$SANDBOX_DIR/example.io" "$IMPORT_SOURCE_DIR/"
# Copy ICA (test.sandbox.dev under sandbox.dev)
cp -r "$SANDBOX_DIR/sandbox.dev" "$IMPORT_SOURCE_DIR/"
cp -r "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev" "$IMPORT_SOURCE_DIR/sandbox.dev/intermediates.d/"

# Create a new context for import
IMPORT_CONTEXT_DIR="$PROJECT_DIR/imported_context"
rm -rf "$IMPORT_CONTEXT_DIR"

echo "--- Import the Root CA (sandbox.dev) to a new context ---"
cargo run -- \
    import \
    "$IMPORT_SOURCE_DIR/sandbox.dev" \
    --context "$IMPORT_CONTEXT_DIR"

echo "--- Import the ICA (test.sandbox.dev) to the same context ---"
cargo run -- \
    import \
    "$IMPORT_SOURCE_DIR/sandbox.dev/intermediates.d/test.sandbox.dev" \
    --context "$IMPORT_CONTEXT_DIR"

echo ""
echo "--- Try to sign a certificate with domain NOT owned by ICA (should FAIL) ---"
cargo run -- \
    --context "$IMPORT_CONTEXT_DIR" \
    --ca test.sandbox.dev \
    --domain www.example.io 2>&1 || echo "Expected failure: ICA can only sign domains under its own domain"

echo ""
echo "--- Sign a certificate using the imported ICA (valid domain) ---"
cargo run -- \
    --context "$IMPORT_CONTEXT_DIR" \
    --ca test.sandbox.dev \
    --domain from_import.test.sandbox.dev

echo ""
echo "--- Check the imported context ---"
cargo run -- check --context "$IMPORT_CONTEXT_DIR"

# Step 12: Verify certificates from imported context using origin Root CA
echo ""
echo "=== Step 12: Verify Imported Context Certificates ==="
echo "--- Verify from_import.test.sandbox.dev using original Root CA ---"
echo "Certificate:"
openssl x509 -in "$IMPORT_CONTEXT_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/certificates.d/from_import.test.sandbox.dev/crt.pem" -noout -subject -issuer
echo "Verify using original Root CA + ICA bundle:"
cat "$SANDBOX_DIR/sandbox.dev/crt.pem" "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/crt.pem" > /tmp/ca-bundle.pem
openssl verify -CAfile /tmp/ca-bundle.pem "$IMPORT_CONTEXT_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/certificates.d/from_import.test.sandbox.dev/crt.pem"
echo ""

# Cleanup import test dirs
rm -rf "$IMPORT_SOURCE_DIR" "$IMPORT_CONTEXT_DIR"

# Step 13: Verify TLS certificates with OpenSSL
echo ""
echo "=== Step 13: Verify TLS Certificates with OpenSSL ==="
echo ""

echo "--- Verify www.example.io (signed by Root CA example.io) ---"
echo "Certificate:"
openssl x509 -in "$SANDBOX_DIR/example.io/certificates.d/www.example.io/crt.pem" -noout -subject -issuer
echo "Verify against Root CA:"
openssl verify -CAfile "$SANDBOX_DIR/example.io/crt.pem" "$SANDBOX_DIR/example.io/certificates.d/www.example.io/crt.pem"
echo "Note: Root CA signed certs do not have fullchain.crt"
echo ""

echo "--- Verify dashboard.ops.example.io (signed by ICA ops.example.io) ---"
echo "Certificate:"
openssl x509 -in "$SANDBOX_DIR/example.io/intermediates.d/ops.example.io/certificates.d/dashboard.ops.example.io/crt.pem" -noout -subject -issuer
cat "$SANDBOX_DIR/example.io/crt.pem" "$SANDBOX_DIR/example.io/intermediates.d/ops.example.io/crt.pem" > /tmp/ca-bundle.pem
echo "Verify using CA bundle (Root CA + ICA):"
openssl verify -CAfile /tmp/ca-bundle.pem "$SANDBOX_DIR/example.io/intermediates.d/ops.example.io/certificates.d/dashboard.ops.example.io/crt.pem"
echo "Fullchain verification (using ICA):"
openssl verify -partial_chain -CAfile "$SANDBOX_DIR/example.io/intermediates.d/ops.example.io/crt.pem" "$SANDBOX_DIR/example.io/intermediates.d/ops.example.io/certificates.d/dashboard.ops.example.io/fullchain.crt"
echo ""

echo "--- Verify jenkins.dev.example.io (signed by ICA dev.example.io) ---"
echo "Certificate:"
openssl x509 -in "$SANDBOX_DIR/example.io/intermediates.d/dev.example.io/certificates.d/jenkins.dev.example.io/crt.pem" -noout -subject -issuer
cat "$SANDBOX_DIR/example.io/crt.pem" "$SANDBOX_DIR/example.io/intermediates.d/dev.example.io/crt.pem" > /tmp/ca-bundle.pem
echo "Verify using CA bundle (Root CA + ICA):"
openssl verify -CAfile /tmp/ca-bundle.pem "$SANDBOX_DIR/example.io/intermediates.d/dev.example.io/certificates.d/jenkins.dev.example.io/crt.pem"
echo "Fullchain verification (using ICA):"
openssl verify -partial_chain -CAfile "$SANDBOX_DIR/example.io/intermediates.d/dev.example.io/crt.pem" "$SANDBOX_DIR/example.io/intermediates.d/dev.example.io/certificates.d/jenkins.dev.example.io/fullchain.crt"
echo ""

echo "--- Verify local.test.sandbox.dev (signed by ICA test.sandbox.dev from different Root CA) ---"
echo "Certificate:"
openssl x509 -in "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/certificates.d/local.test.sandbox.dev/crt.pem" -noout -subject -issuer
cat "$SANDBOX_DIR/sandbox.dev/crt.pem" "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/crt.pem" > /tmp/ca-bundle.pem
echo "Verify using CA bundle (Root CA + ICA):"
openssl verify -CAfile /tmp/ca-bundle.pem "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/certificates.d/local.test.sandbox.dev/crt.pem"
echo "Fullchain verification (using ICA):"
openssl verify -partial_chain -CAfile "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/crt.pem" "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/certificates.d/local.test.sandbox.dev/fullchain.crt"
echo ""

echo "--- Verify multi.example.io (signed by Root CA example.io, with wildcard and IP) ---"
echo "Certificate Subject:"
openssl x509 -in "$SANDBOX_DIR/example.io/certificates.d/multi.example.io/crt.pem" -noout -subject
echo "Subject Alternative Names:"
openssl x509 -in "$SANDBOX_DIR/example.io/certificates.d/multi.example.io/crt.pem" -noout -text | grep -A 2 "Subject Alternative Name"
echo "Verify using Root CA:"
openssl verify -CAfile "$SANDBOX_DIR/example.io/crt.pem" "$SANDBOX_DIR/example.io/certificates.d/multi.example.io/crt.pem"
echo "Note: Root CA signed certs do not have fullchain.crt"
echo ""

# Step 14: Verify fullchain certificate order for ICA-signed certificates
echo ""
echo "=== Step 14: Verify Fullchain Certificate Order ==="
echo "Only ICA-signed certificates have fullchain.crt"
echo "Fullchain order: Server Cert -> ICA Cert (no Root CA)"
echo ""

verify_fullchain_order() {
    local fullchain_path=$1
    local cert_name=$2

    if [ ! -f "$fullchain_path" ]; then
        echo "--- $cert_name: No fullchain (Root CA signed) - OK"
        return
    fi

    echo "--- Checking $cert_name fullchain ---"
    local cert_count=$(grep -c "BEGIN CERTIFICATE" "$fullchain_path")
    echo "Found $cert_count certificate(s) in fullchain"

    # Verify using ICA certificate
    local cert_dir=$(dirname "$fullchain_path")
    local intermediates_dir=$(dirname "$cert_dir")
    local ica_crt="$intermediates_dir/crt.pem"

    if [ -f "$ica_crt" ]; then
        if openssl verify -partial_chain -CAfile "$ica_crt" "$fullchain_path" >/dev/null 2>&1; then
            echo "✓ $cert_name fullchain verification: PASSED"
        else
            echo "✗ $cert_name fullchain verification: FAILED"
        fi
    else
        echo "? $cert_name: ICA cert not found for verification"
    fi
    echo ""
}

# Verify ICA-signed certificate fullchain
verify_fullchain_order "$SANDBOX_DIR/example.io/intermediates.d/ops.example.io/certificates.d/dashboard.ops.example.io/fullchain.crt" "dashboard.ops.example.io"

verify_fullchain_order "$SANDBOX_DIR/example.io/intermediates.d/dev.example.io/certificates.d/jenkins.dev.example.io/fullchain.crt" "jenkins.dev.example.io"

verify_fullchain_order "$SANDBOX_DIR/sandbox.dev/intermediates.d/test.sandbox.dev/certificates.d/local.test.sandbox.dev/fullchain.crt" "local.test.sandbox.dev"

# Root CA signed certs should NOT have fullchain.crt
verify_fullchain_order "$SANDBOX_DIR/example.io/certificates.d/www.example.io/fullchain.crt" "www.example.io"

verify_fullchain_order "$SANDBOX_DIR/example.io/certificates.d/multi.example.io/fullchain.crt" "multi.example.io (with wildcard)"

# Step 15: Final verification - all server certs verified by root CA
echo ""
echo "=== Step 15: Final Verification - All Certs Verified by Root CA ==="

verify_cert() {
    local cert_path=$1
    local root_ca_path=$2
    local name=$3
    local chain_type=$4
    
    if [ ! -f "$cert_path" ]; then
        echo "✗ $name ($chain_type) not found: $cert_path"
        return
    fi
    
    if [[ "$cert_path" == *"intermediates.d"* ]]; then
        local ica_name=$(basename "$(dirname "$(dirname "$(dirname "$cert_path")")")")
        local ica_dir=$(dirname "$cert_path")
        ica_dir=$(dirname "$ica_dir")
        ica_dir=$(dirname "$ica_dir")
        ica_dir=$(dirname "$ica_dir")
        local ica_crt="$ica_dir/$ica_name/crt.pem"
        
        if [ -f "$ica_crt" ]; then
            cat "$root_ca_path" "$ica_crt" > /tmp/verify-bundle.pem
        else
            echo "✗ $name: ICA cert not found: $ica_crt"
            return
        fi
    else
        cp "$root_ca_path" /tmp/verify-bundle.pem
    fi
    
    if openssl verify -CAfile /tmp/verify-bundle.pem "$cert_path" > /tmp/verify-result.txt 2>&1; then
        echo "✓ $name ($chain_type)"
    else
        echo "✗ $name failed: $(cat /tmp/verify-result.txt)"
    fi
    rm -f /tmp/verify-bundle.pem /tmp/verify-result.txt
}

verify_fullchain() {
    local fullchain_path=$1
    local root_ca_path=$2
    local name=$3
    
    if [ ! -f "$fullchain_path" ]; then
        return
    fi
    
    # -partial_chain verifies the cert chain ends at our root (doesn't need full trust store)
    if openssl verify -partial_chain -CAfile "$root_ca_path" "$fullchain_path" > /tmp/verify-result.txt 2>&1; then
        echo "✓ $name (fullchain)"
    else
        echo "✗ $name fullchain failed: $(cat /tmp/verify-result.txt)"
    fi
    rm -f /tmp/verify-result.txt
}

echo "--- Discovering all Root CAs and certificates ---"

for root_ca in "$SANDBOX_DIR"/*/crt.pem; do
    [ -f "$root_ca" ] || continue
    root_ca_dir=$(dirname "$root_ca")
    root_ca_name=$(basename "$root_ca_dir")
    
    [[ "$root_ca_name" == "certs.json" ]] && continue
    
    echo ""
    echo "=== Root CA: $root_ca_name ==="
    
    while IFS= read -r cert; do
        domain=$(basename "$(dirname "$cert")")
        verify_cert "$cert" "$root_ca" "$domain" "root-signed"
    done < <(find "$root_ca_dir/certificates.d" -name "crt.pem" 2>/dev/null || true)
    
    # Root CA directory does not have fullchain.crt
    
    for ica in "$root_ca_dir"/intermediates.d/*/crt.pem; do
        [ -f "$ica" ] || continue
        ica_name=$(basename "$(dirname "$ica")")
        
        ica_dir=$(dirname "$ica")
        # ICA directory does not have fullchain.crt
        
        while IFS= read -r cert; do
            domain=$(basename "$(dirname "$cert")")
            verify_cert "$cert" "$root_ca" "$domain" "ICA-signed"
        done < <(find "$ica_dir/certificates.d" -name "crt.pem" 2>/dev/null || true)
    done
done

echo ""
echo "All certificates verified!"

# Step 16: Test Export functionality
echo ""
echo "=== Step 16: Test Export Functionality ==="

# Export a server certificate to current directory
EXPORT_DIR="$PROJECT_DIR/export_test"
rm -rf "$EXPORT_DIR"
mkdir -p "$EXPORT_DIR"
cd "$EXPORT_DIR"

echo "--- Exporting www.example.io certificate ---"
cargo run -- \
    --context "$SANDBOX_DIR" export www.example.io

echo ""
echo "--- Verifying exported files ---"
if [ -f "www.example.io.crt" ] && [ -f "www.example.io.key" ]; then
    echo "✓ Certificate exported successfully!"
    echo "  - www.example.io.crt"
    echo "  - www.example.io.key"
    
    # Verify the exported certificate
    echo ""
    echo "--- Exported Certificate Details ---"
    openssl x509 -in www.example.io.crt -noout -subject -dates
else
    echo "✗ Export failed!"
fi

# Cleanup export test
cd "$PROJECT_DIR"
rm -rf "$EXPORT_DIR"

# Cleanup
rm -f /tmp/ca-bundle.pem

# Show directory structure
echo "=== Directory Structure ==="
tree "$SANDBOX_DIR" -L 4 || find "$SANDBOX_DIR" -maxdepth 4 -type f -name "crt.pem" -o -name "meta.json" | head -30

echo ""
echo "=== Quickstart Complete! ==="
echo "Sandbox location: $SANDBOX_DIR"
echo ""
echo "To clean up: rm -rf $SANDBOX_DIR"
