#!/usr/bin/env bash
set -euo pipefail
mkdir -p dist
# Build a WASM bundle with the decision entrypoint, extract policy.wasm.
opa build -t wasm -e gateway/decision -o dist/bundle.tar.gz policy/bundle
tar -xzf dist/bundle.tar.gz -C dist /policy.wasm
echo "built dist/policy.wasm"
