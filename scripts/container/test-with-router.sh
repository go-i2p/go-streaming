#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.router-tests.yml}"

cd "${ROOT_DIR}"

echo "[router-tests] Building router and test services..."
docker compose -f "${COMPOSE_FILE}" build

cleanup() {
	docker compose -f "${COMPOSE_FILE}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[router-tests] Starting router service..."
docker compose -f "${COMPOSE_FILE}" up -d i2p-router

echo "[router-tests] Running Go tests against router service..."
docker compose -f "${COMPOSE_FILE}" run --rm router-tests
