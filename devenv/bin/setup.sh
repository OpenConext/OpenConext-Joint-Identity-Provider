#!/usr/bin/env bash
# Prepares the JointIdentityProvider (JIP) POC environment without creating containers. Safe to re-run.
#  1. checks out OpenConext-devconf and EngineBlock 7.2.1 at the pinned commits
#  2. installs EngineBlock's PHP dependencies (host PHP 8.5 + Composer)
#  3. creates devenv/.env with a random SBS API token
#  4. creates devconf's dev CA and wildcard certificate (*.dev.openconext.local) if missing
#  5. renders the HAProxy config with the JIP, mock DEZI and test SP backends
#  6. installs the EngineBlock SBS drop-in (config/packages/dev/zz_jip_sbs.yaml)
#  7. creates JIP's mock keys and grants the container's web-server user ACL access to them and var/
#  8. creates the mock DEZI provider's signing keys and grants the same ACL access to them and its var/
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/_env.sh"
source "${JIP_DEVENV_DIR}/bin/_haproxy.sh"

info() { printf '\e[1;32m==>\e[0m %s\n' "$*"; }
fail() { printf '\e[1;31mERROR:\e[0m %s\n' "$*" >&2; exit 1; }

for cmd in git docker openssl; do
    command -v "$cmd" >/dev/null || fail "$cmd is required"
done
docker compose version >/dev/null 2>&1 || fail "docker compose v2 is required"
openssl version | grep -q '^OpenSSL 3' || fail "OpenSSL 3 is required by devconf's create_dev_ca.sh"

checkout() { # <dir> <repo> <ref> <expected commit>
    local dir="$1" repo="$2" ref="$3" expected="$4"
    if [[ ! -d "$dir/.git" ]]; then
        info "Cloning $repo ($ref)"
        git clone --quiet "$repo" "$dir"
    fi
    if [[ "$(git -C "$dir" rev-parse HEAD)" != "$expected" ]]; then
        [[ -z "$(git -C "$dir" status --porcelain --untracked-files=no)" ]] \
            || fail "$dir has local changes; refusing to switch it to $ref"
        git -C "$dir" fetch --quiet --tags origin
        git -C "$dir" -c advice.detachedHead=false checkout --quiet "$ref"
    fi
    [[ "$(git -C "$dir" rev-parse HEAD)" == "$expected" ]] \
        || fail "$dir is at $(git -C "$dir" rev-parse HEAD), expected $expected ($ref)"
    info "$(basename "$dir") at $ref ($expected)"
}

mkdir -p "${JIP_DEVENV_DIR}/upstream"
checkout "${DEVCONF_DIR}" "${DEVCONF_REPO}" "${DEVCONF_REF}" "${DEVCONF_REF}"
checkout "${ENGINE_CODE_PATH}" "${ENGINE_REPO}" "${ENGINE_TAG}" "${ENGINE_COMMIT}"

if [[ ! -f "${ENGINE_CODE_PATH}/vendor/autoload.php" ]]; then
    if command -v php >/dev/null && command -v composer >/dev/null; then
        info "Installing EngineBlock PHP dependencies on the host"
        (cd "${ENGINE_CODE_PATH}" && composer install --no-interaction --prefer-dist)
    else
        fail "EngineBlock needs 'composer install' (PHP 8.5). Install PHP 8.5 + Composer, or run it in the engine container after startup."
    fi
fi

if [[ ! -f "${JIP_DEVENV_DIR}/.env" ]]; then
    info "Creating devenv/.env with a new SBS API token"
    sed "s|^JIP_SBS_API_TOKEN=.*|JIP_SBS_API_TOKEN=$(openssl rand -hex 32)|" \
        "${JIP_DEVENV_DIR}/env.dist" > "${JIP_DEVENV_DIR}/.env"
    chmod 600 "${JIP_DEVENV_DIR}/.env"
fi

haproxy_dir="${DEVCONF_CORE_DIR}/haproxy"
if [[ ! -f "${haproxy_dir}/haproxy.crt" || ! -f "${haproxy_dir}/haproxy.pem" ]]; then
    info "Creating devconf's dev CA and *.dev.openconext.local certificate"
    # The script writes a temporary key directory into the current directory.
    tmp="$(mktemp -d)"
    (cd "$tmp" && "${DEVCONF_CORE_DIR}/scripts/create_dev_ca.sh" >/dev/null)
    rmdir "$tmp"
fi
mkdir -p "$(dirname "${DEV_CA_CERT}")"
cp "${haproxy_dir}/haproxy.crt" "${DEV_CA_CERT}"
info "Dev CA certificate: ${DEV_CA_CERT}"

# Keep credentials out of proxy logs too: the default HTTP log includes the full request URI.
info "Rendering HAProxy config with the JIP backends"
generated="${JIP_DEVENV_DIR}/haproxy/generated"
mkdir -p "$generated"
{ cat "${haproxy_dir}/backends.map"; echo; cat "${JIP_DEVENV_DIR}/haproxy/jip-backends.map"; } \
    | sed '/^[[:space:]]*$/d' > "${generated}/backends.map"
jip_render_haproxy "${haproxy_dir}/haproxy.cfg" "${JIP_DEVENV_DIR}/haproxy/jip-backends.cfg" \
    "${generated}/haproxy.cfg" || fail "HAProxy rendering failed; the previous configuration was kept"

info "Installing the EngineBlock SBS drop-in"
install -m 644 "${JIP_DEVENV_DIR}/engine/zz_jip_sbs.yaml" \
    "${ENGINE_CODE_PATH}/config/packages/dev/zz_jip_sbs.yaml"

if [[ -x "${JIP_CODE_PATH}/bin/init-mock-keys" ]]; then
    command -v setfacl >/dev/null || fail "setfacl is required (package acl)"
    "${JIP_CODE_PATH}/bin/init-mock-keys"
    info "Granting the JIP container's web-server user (uid ${JIP_CONTAINER_WEB_UID}) access to keys/ and var/"
    web="u:${JIP_CONTAINER_WEB_UID}"
    keys="${JIP_CODE_PATH}/keys"
    # Search on the 0700 key directories and read on the key files only: no listing, no writing.
    setfacl -m "${web}:--x" "$keys" "$keys/mock"
    setfacl -m "${web}:r--" "$keys"/mock/*.pem "$keys"/mock/*.crt
    # var/: read-write for the web-server user and this user, inherited by new entries; no world access.
    # Entries the container created belong to its user and already carry the inherited ACL.
    var="${JIP_CODE_PATH}/var"
    mkdir -p "$var"
    find "$var" -user "$(id -u)" ! -type l -exec chmod o-rwx {} + \
        -exec setfacl -m "${web}:rwX,u:$(id -u):rwX" {} +
    find "$var" -user "$(id -u)" -type d -exec setfacl -d -m "${web}:rwX,u:$(id -u):rwX" {} +
fi

if [[ -x "${MOCK_DEZI_CODE_PATH}/bin/init-keys" ]]; then
    command -v setfacl >/dev/null || fail "setfacl is required (package acl)"
    "${MOCK_DEZI_CODE_PATH}/bin/init-keys"
    info "Granting the mock DEZI container's web-server user (uid ${JIP_CONTAINER_WEB_UID}) access to keys/ and var/"
    web="u:${JIP_CONTAINER_WEB_UID}"
    keys="${MOCK_DEZI_CODE_PATH}/keys"
    setfacl -m "${web}:--x" "$keys"
    setfacl -m "${web}:r--" "$keys"/*.pem
    var="${MOCK_DEZI_CODE_PATH}/var"
    mkdir -p "$var"
    find "$var" -user "$(id -u)" ! -type l -exec chmod o-rwx {} + \
        -exec setfacl -m "${web}:rwX,u:$(id -u):rwX" {} +
    find "$var" -user "$(id -u)" -type d -exec setfacl -d -m "${web}:rwX,u:$(id -u):rwX" {} +
fi

cat <<EOF

Setup complete. Manual steps that need root or a browser (see devenv/README.md):

  1. Add to /etc/hosts:
     127.0.0.1 ${JIP_HOSTNAMES[*]}
     ::1 ${JIP_HOSTNAMES[*]}
  2. Trust ${DEV_CA_CERT} in your browser (name-constrained to .dev.openconext.local).
  3. Verify: devenv/bin/check.sh
EOF
