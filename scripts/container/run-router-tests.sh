#!/bin/sh
set -eu

I2CP_HOST="${I2CP_HOST:-i2p-router}"
I2CP_PORT="${I2CP_PORT:-7654}"
ROUTER_START_TIMEOUT_SECONDS="${ROUTER_START_TIMEOUT_SECONDS:-180}"
TEST_FLAGS="${TEST_FLAGS:-}"

# go-i2cp clients read router endpoint from ${I2CP_HOME}/.i2cp.conf by default.
# Populate that config so every test binary started by `go test` uses compose router settings.
TMP_I2CP_HOME="$(mktemp -d /tmp/go-streaming-i2cp-home.XXXXXX)"
TMP_I2CP_CONF="${TMP_I2CP_HOME}/.i2cp.conf"
trap 'rm -rf "${TMP_I2CP_HOME}"' EXIT INT TERM
cat > "${TMP_I2CP_CONF}" <<EOF
i2cp.tcp.host=${I2CP_HOST};
i2cp.tcp.port=${I2CP_PORT};
EOF
export I2CP_HOME="${TMP_I2CP_HOME}"
unset GO_I2CP_CONF

echo "[router-tests] Waiting for I2CP on ${I2CP_HOST}:${I2CP_PORT}..."
go run ./scripts/container/wait-for-tcp.go \
    -host "${I2CP_HOST}" \
    -port "${I2CP_PORT}" \
    -timeout "${ROUTER_START_TIMEOUT_SECONDS}s"

echo "[router-tests] I2CP is reachable. Running Go test suite..."

# -count=1 disables test result caching so every container run is a fresh end-to-end check.
go test -count=1 ${TEST_FLAGS} ./...

echo "[router-tests] Test suite completed successfully."
