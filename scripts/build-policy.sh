#!/usr/bin/env bash
set -euo pipefail
mkdir -p dist
# Build a WASM bundle with the decision entrypoint, extract policy.wasm.
opa build -t wasm -e gateway/decision -o dist/bundle.tar.gz policy/bundle

# OPA stores bundle members with a leading slash (/policy.wasm), so tar emits a
# "Removing leading '/'" notice on success. Capture output and surface it only on
# failure, so a clean build stays quiet without hiding real extraction errors.
if ! tar_out=$(tar -xzf dist/bundle.tar.gz -C dist /policy.wasm 2>&1); then
  printf '%s\n' "$tar_out" >&2
  echo "error: failed to extract policy.wasm from the OPA bundle" >&2
  exit 1
fi

if [ ! -s dist/policy.wasm ]; then
  echo "error: dist/policy.wasm missing or empty after extraction" >&2
  exit 1
fi

echo "built dist/policy.wasm"
