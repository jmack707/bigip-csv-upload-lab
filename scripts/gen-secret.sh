#!/usr/bin/env bash
# Write .env with a random VALIDATION_SECRET shared by the validator and the upload application.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if grep -q '^VALIDATION_SECRET=' .env 2>/dev/null; then echo ".env already has VALIDATION_SECRET"; exit 0; fi
umask 077
echo "VALIDATION_SECRET=$(openssl rand -hex 32)" >> .env
echo "wrote .env (git-ignored)"
