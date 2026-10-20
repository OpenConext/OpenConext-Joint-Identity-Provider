#!/usr/bin/env bash
# docker compose for devconf core + EngineBlock 7.2.1 development override + JIP overlay.
# Usage: devenv/bin/compose.sh <docker compose arguments>, e.g. "config", "up -d --wait", "ps".
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/_env.sh"

[[ -f "${JIP_DEVENV_DIR}/.env" ]] || { echo "devenv/.env missing: run devenv/bin/setup.sh first" >&2; exit 1; }

if [[ ",${COMPOSE_PROFILES:-}," == *",jip,"* ]]; then
    for p in "${JIP_CODE_PATH}" "${MOCK_DEZI_CODE_PATH}" "${JIP_TEST_SP_CODE_PATH}"; do
        [[ -d "$p" ]] || { echo "Profile jip needs ${p}; it does not exist yet" >&2; exit 1; }
    done
fi

# Run from devconf core so project name ("core") and .env lookup match devconf's own scripts/init.sh.
cd "${DEVCONF_CORE_DIR}"
exec docker compose "${compose_files[@]}" "$@"
