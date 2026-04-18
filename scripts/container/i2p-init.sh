#!/bin/sh
set -e

# Patch I2CP and other services to listen on all interfaces so the compose network can reach them
echo "[init] Patching I2P config for compose network access..."

# Replace bind addresses in all config files from 127.0.0.1 to 0.0.0.0
find /i2p -name '*.config' -type f -exec sed -i 's/127\.0\.0\.1/0.0.0.0/g' {} + || true

# Clear any stale config state
rm -rf /i2p/.i2p/eepget.exe /i2p/.i2p/*.cache 2>/dev/null || true

echo "[init] Launching I2P router..."
exec /startapp.sh
