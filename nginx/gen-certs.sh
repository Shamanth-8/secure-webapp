#!/usr/bin/env bash
# Generates a self-signed TLS cert for local HTTPS. Certs are gitignored —
# run this once before `docker compose up --build`.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -subj "/CN=localhost" \
  -keyout certs/server.key -out certs/server.crt
chmod 600 certs/server.key
echo "Wrote nginx/certs/server.crt and nginx/certs/server.key"
