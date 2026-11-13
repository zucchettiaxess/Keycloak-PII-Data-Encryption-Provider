#!/usr/bin/env bash
# End-to-end tests against a real Keycloak + PostgreSQL + OpenLDAP + Mailpit stack.
#
#   mvn clean package            (or the Docker build command in the README)
#   e2e/run.sh                   run all tests, then tear the stack down
#   e2e/run.sh KnownLeaks        run one class (or Class.test_name)
#   KEEP=1 e2e/run.sh            leave the stack running afterwards
#   KEYCLOAK_VERSION=26.8.2 e2e/run.sh
#
# Requires Docker (compose v2) and Python 3. No Python packages needed.
set -euo pipefail
cd "$(dirname "$0")"

JAR=../target/keycloak-pii-data-encryption.jar
[ -f "$JAR" ] || { echo "Missing $JAR: build the provider first (mvn clean package)." >&2; exit 2; }

teardown() { [ "${KEEP:-0}" = "1" ] || docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap teardown EXIT

docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose up -d
if [ $# -gt 0 ]; then
  python3 -m unittest -v "${@/#/test_encryption.}"
else
  python3 -m unittest -v test_encryption
fi
