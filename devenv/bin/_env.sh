#!/usr/bin/env bash
# Shared by the devenv scripts: loads devenv/.env and derives absolute paths.

JIP_DEVENV_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
JIP_ROOT="$(cd -- "${JIP_DEVENV_DIR}/.." && pwd -P)"

if [[ -f "${JIP_DEVENV_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${JIP_DEVENV_DIR}/.env"
    set +a
else
    set -a
    # shellcheck disable=SC1091
    source "${JIP_DEVENV_DIR}/env.dist"
    set +a
fi

export JIP_DEVENV_DIR JIP_ROOT
export DEVCONF_DIR="${DEVCONF_DIR:-${JIP_DEVENV_DIR}/upstream/OpenConext-devconf}"
export DEVCONF_CORE_DIR="${DEVCONF_DIR}/core"
export ENGINE_CODE_PATH="${ENGINE_CODE_PATH:-${JIP_DEVENV_DIR}/upstream/OpenConext-engineblock-${ENGINE_TAG}}"
export JIP_CODE_PATH="${JIP_CODE_PATH:-${JIP_ROOT}/jip}"
export MOCK_DEZI_CODE_PATH="${MOCK_DEZI_CODE_PATH:-${JIP_ROOT}/mock-dezi}"
export JIP_TEST_SP_CODE_PATH="${JIP_TEST_SP_CODE_PATH:-${JIP_ROOT}/test-sp}"
export DEV_CA_CERT="${JIP_DEVENV_DIR}/certs/openconext-dev-ca.crt"
# www-data in the php85-apache2 base image (checked 19 October 2026); used for ACLs on bind mounts.
export JIP_CONTAINER_WEB_UID="${JIP_CONTAINER_WEB_UID:-33}"

JIP_HOSTNAMES=(
    engine.dev.openconext.local
    engine-api.dev.openconext.local
    manage.dev.openconext.local
    mujina-idp.dev.openconext.local
    profile.dev.openconext.local
    jip.dev.openconext.local
    mock-dezi.dev.openconext.local
    jip-test-sp.dev.openconext.local
)

compose_files=(
    -f "${DEVCONF_CORE_DIR}/docker-compose.yml"
    -f "${DEVCONF_CORE_DIR}/engine/docker-compose.override.yml"
    -f "${JIP_DEVENV_DIR}/compose/jip.override.yml"
)
