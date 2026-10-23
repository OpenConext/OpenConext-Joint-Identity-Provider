#!/usr/bin/env bash
# Read-only verification of the JointIdentityProvider (JIP) POC environment. Never creates or starts containers.
# OK = verified, MISSING = prerequisite not (yet) supplied, FAIL = wrong configuration.
set -uo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/_env.sh"
source "${JIP_DEVENV_DIR}/bin/_haproxy.sh"

fails=0; missing=0
ok()   { printf '  \e[32mOK\e[0m      %s\n' "$*"; }
miss() { printf '  \e[33mMISSING\e[0m %s\n' "$*"; missing=$((missing + 1)); }
bad()  { printf '  \e[31mFAIL\e[0m    %s\n' "$*"; fails=$((fails + 1)); }
section() { printf '\n\e[1m%s\e[0m\n' "$*"; }
compose() { "${JIP_DEVENV_DIR}/bin/compose.sh" "$@"; }

section "Host runtime"
docker compose version --short >/dev/null 2>&1 && ok "docker compose $(docker compose version --short)" || bad "docker compose v2 missing"
if command -v php >/dev/null; then
    v=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    [[ "$v" == "8.5" ]] && ok "host PHP $(php -r 'echo PHP_VERSION;')" || bad "host PHP $v (8.5 expected)"
    php -r 'exit(extension_loaded("gmp") ? 0 : 1);' && ok "host ext-gmp" \
        || miss "host ext-gmp (needed to run libcheck/JIP tests on the host; the container image has it)"
else
    miss "host PHP 8.5 (only needed for host-side EngineBlock install and checks)"
fi

section "Checkouts"
if [[ -d "${DEVCONF_DIR}/.git" ]]; then
    head=$(git -C "${DEVCONF_DIR}" rev-parse HEAD)
    [[ "$head" == "${DEVCONF_REF}" ]] && ok "devconf at ${head}" || bad "devconf at ${head}, expected ${DEVCONF_REF}"
else
    miss "devconf checkout (${DEVCONF_DIR}): run devenv/bin/setup.sh"
fi
if [[ -d "${ENGINE_CODE_PATH}/.git" ]]; then
    head=$(git -C "${ENGINE_CODE_PATH}" rev-parse HEAD)
    [[ "$head" == "${ENGINE_COMMIT}" ]] && ok "EngineBlock ${ENGINE_TAG} at ${head}" \
        || bad "EngineBlock at ${head}, expected ${ENGINE_TAG} (${ENGINE_COMMIT})"
    grep -q "'attributes' => \$this->attributes" \
        "${ENGINE_CODE_PATH}/src/OpenConext/EngineBlockBundle/Sbs/Dto/AuthzRequest.php" \
        && ok "EngineBlock start request carries 'attributes' (§9 item 2)" \
        || bad "EngineBlock start request lacks 'attributes'"
    [[ -f "${ENGINE_CODE_PATH}/vendor/autoload.php" ]] && ok "EngineBlock vendor/ installed" \
        || miss "EngineBlock vendor/: run devenv/bin/setup.sh"
else
    miss "EngineBlock checkout (${ENGINE_CODE_PATH}): run devenv/bin/setup.sh"
fi
for p in "${JIP_CODE_PATH}" "${MOCK_DEZI_CODE_PATH}" "${JIP_TEST_SP_CODE_PATH}"; do
    [[ -d "$p" ]] && ok "code path $p" || miss "code path $p (check JIP_CODE_PATH, MOCK_DEZI_CODE_PATH and JIP_TEST_SP_CODE_PATH in devenv/.env)"
done

section "JIP application (host PHP, mock configuration)"
if [[ ! -f "${JIP_CODE_PATH}/vendor/autoload_runtime.php" ]]; then
    miss "JIP vendor/: run 'composer install' in ${JIP_CODE_PATH}"
elif ! command -v php >/dev/null; then
    miss "host PHP 8.5 (needed to run JIP's checks on the host)"
else
    keys_present=1
    for f in ggd-signing.pem ggd-signing.crt ggd-decryption.pem ggd-decryption.crt; do
        [[ -f "${JIP_CODE_PATH}/keys/mock/$f" ]] || keys_present=0
    done
    if [[ $keys_present -eq 1 ]]; then
        out=$(cd "${JIP_CODE_PATH}" && APP_ENV=dev APP_DEBUG=0 JIP_CONFIG_FILE=config/jip/mock.yaml \
            CONNECTOR_ENVIRONMENT=mock EB_API_TOKEN="${JIP_SBS_API_TOKEN}" \
            php bin/console jip:config:validate --no-ansi 2>&1)
        [[ $? -eq 0 ]] && ok "JIP startup checks pass on config/jip/mock.yaml" \
            || bad "JIP startup checks fail: $(grep -E '^ \* ' <<<"$out" | head -5 | tr '\n' ' ')"
    else
        miss "JIP mock keys: run ${JIP_CODE_PATH}/bin/init-mock-keys"
    fi
    git -C "${JIP_ROOT}" check-ignore -q "${JIP_CODE_PATH}/keys/mock/ggd-signing.pem" \
        && ok "JIP keys/ is git-ignored" || bad "JIP keys/ is not git-ignored"
fi

section "JIP container access (web-server uid ${JIP_CONTAINER_WEB_UID}, ACLs on the bind mount)"
acl_entry() { # <path> <expected getfacl line>: the named-user entry, not reduced by the mask
    getfacl -cn "$1" 2>/dev/null | grep -qx "$2"
}
keys="${JIP_CODE_PATH}/keys"
if [[ -d "$keys/mock" ]]; then
    for d in "$keys" "$keys/mock"; do
        acl_entry "$d" "user:${JIP_CONTAINER_WEB_UID}:--x" && [[ "$(stat -c %a "$d")" == 710 ]] \
            && ok "${d#"${JIP_ROOT}/"}: search only for the web-server user, no other access" \
            || bad "${d#"${JIP_ROOT}/"}: expected mode 700 plus ACL user:${JIP_CONTAINER_WEB_UID}:--x (run devenv/bin/setup.sh)"
    done
    for f in "$keys"/mock/*.pem "$keys"/mock/*.crt; do
        acl_entry "$f" "user:${JIP_CONTAINER_WEB_UID}:r--" \
            && ok "${f#"${JIP_ROOT}/"}: readable by the web-server user" \
            || bad "${f#"${JIP_ROOT}/"}: ACL user:${JIP_CONTAINER_WEB_UID}:r-- missing (run devenv/bin/setup.sh)"
    done
    [[ -z "$(find "$keys" -name '*.pem' -perm /o=rwx)" ]] && ok "no private key is world-accessible" \
        || bad "a private key under ${keys} is world-accessible"
else
    miss "JIP keys: run devenv/bin/setup.sh"
fi
var="${JIP_CODE_PATH}/var"
if [[ -d "$var" ]]; then
    acl_entry "$var" "user:${JIP_CONTAINER_WEB_UID}:rwx" \
        && getfacl -cn "$var" 2>/dev/null | grep -qx "default:user:${JIP_CONTAINER_WEB_UID}:rwx" \
        && ok "var/: read-write for the web-server user, inherited by new entries" \
        || bad "var/: ACL for uid ${JIP_CONTAINER_WEB_UID} missing (run devenv/bin/setup.sh)"
    [[ -z "$(find "$var" ! -type l -perm /o=w)" ]] && ok "nothing under var/ is world-writable" \
        || bad "world-writable entries under var/ (run devenv/bin/setup.sh)"
else
    miss "JIP var/: run devenv/bin/setup.sh"
fi

section "Mock DEZI provider (host PHP; read-only check, state kept)"
mock_keys="${MOCK_DEZI_CODE_PATH}/keys"
if [[ ! -f "${MOCK_DEZI_CODE_PATH}/vendor/autoload_runtime.php" ]]; then
    miss "mock DEZI vendor/: run 'composer install' in ${MOCK_DEZI_CODE_PATH}"
elif ! command -v php >/dev/null; then
    miss "host PHP 8.5 (needed to check the mock DEZI provider on the host)"
elif [[ ! -f "$mock_keys/rogue.pem" ]]; then
    miss "mock DEZI keys: run devenv/bin/setup.sh (or ${MOCK_DEZI_CODE_PATH}/bin/init-keys)"
else
    out=$(cd "${MOCK_DEZI_CODE_PATH}" && APP_ENV=dev APP_DEBUG=0 php bin/console mock-dezi:reset --check --no-ansi 2>&1)
    [[ $? -eq 0 ]] && ok "mock DEZI configuration, fixtures, client certificates and keys are usable" \
        || bad "mock DEZI check fails: $(tail -1 <<<"$out")"
    git -C "${JIP_ROOT}" check-ignore -q "$mock_keys/rogue.pem" \
        && ok "mock DEZI keys/ is git-ignored" || bad "mock DEZI keys/ is not git-ignored"
    keys_acl=1
    acl_entry "$mock_keys" "user:${JIP_CONTAINER_WEB_UID}:--x" || keys_acl=0
    for f in "$mock_keys"/*.pem; do
        acl_entry "$f" "user:${JIP_CONTAINER_WEB_UID}:r--" || keys_acl=0
    done
    [[ $keys_acl -eq 1 ]] \
        && ok "mock DEZI keys/: search and read for the web-server user only" \
        || bad "mock DEZI keys/: ACL for uid ${JIP_CONTAINER_WEB_UID} missing (run devenv/bin/setup.sh)"
    [[ -z "$(find "$mock_keys" -name '*.pem' -perm /o=rwx)" ]] && ok "no mock DEZI private key is world-accessible" \
        || bad "a mock DEZI private key is world-accessible"
    getfacl -cn "${MOCK_DEZI_CODE_PATH}/var" 2>/dev/null | grep -qx "default:user:${JIP_CONTAINER_WEB_UID}:rwx" \
        && ok "mock DEZI var/: read-write for the web-server user, inherited by new entries" \
        || bad "mock DEZI var/: ACL for uid ${JIP_CONTAINER_WEB_UID} missing (run devenv/bin/setup.sh)"
fi

section "Local configuration"
[[ -f "${JIP_DEVENV_DIR}/.env" ]] && ok "devenv/.env" || miss "devenv/.env: run devenv/bin/setup.sh"
if [[ ${#JIP_SBS_API_TOKEN} -ge 32 ]]; then ok "SBS API token set (${#JIP_SBS_API_TOKEN} chars)"; else bad "SBS API token shorter than 32 characters"; fi
for f in backends.map haproxy.cfg; do
    [[ -s "${JIP_DEVENV_DIR}/haproxy/generated/$f" ]] || { bad "haproxy/generated/$f missing"; continue; }
done
jip_haproxy_logging_is_safe "${JIP_DEVENV_DIR}/haproxy/generated/haproxy.cfg" \
    && ok "HAProxy logs omit request URIs and headers" \
    || bad "HAProxy logging is unsafe or unsupported: run devenv/bin/setup.sh"
for be in jip_be mock-dezi_be jip-test-sp_be; do
    grep -q "^backend ${be}$" "${JIP_DEVENV_DIR}/haproxy/generated/haproxy.cfg" 2>/dev/null \
        && grep -q " ${be}$" "${JIP_DEVENV_DIR}/haproxy/generated/backends.map" \
        && ok "HAProxy routes to ${be}" || bad "HAProxy route ${be} missing"
done
dropin="${ENGINE_CODE_PATH}/config/packages/dev/zz_jip_sbs.yaml"
cmp -s "$dropin" "${JIP_DEVENV_DIR}/engine/zz_jip_sbs.yaml" && ok "EngineBlock SBS drop-in installed" \
    || bad "EngineBlock SBS drop-in missing or outdated: run devenv/bin/setup.sh"

section "EngineBlock configuration (compiled on the host, APP_ENV=dev)"
if command -v php >/dev/null && [[ -f "${ENGINE_CODE_PATH}/vendor/autoload.php" ]]; then
    for param in feature_enable_sram_interrupt sram.base_url sram.verify_peer sram.api_token http_client.timeout sram.allowed_attributes; do
        # bin/console reads $_ENV; APP_SECRET is devconf's development default.
        val=$(cd "${ENGINE_CODE_PATH}" && APP_ENV=dev APP_DEBUG=true APP_SECRET=secret \
            php -d variables_order=EGPCS bin/console debug:container --env=dev \
            --parameter="$param" --format=json 2>/dev/null | php -r 'echo json_encode(array_values(json_decode(stream_get_contents(STDIN), true))[0] ?? null, JSON_UNESCAPED_SLASHES);')
        case "$param" in
            feature_enable_sram_interrupt|sram.verify_peer) [[ "$val" == "true" ]] ;;
            sram.base_url) [[ "$val" == '"https://jip.dev.openconext.local/"' ]] ;;
            sram.api_token) [[ "$val" == '"%env(JIP_SBS_API_TOKEN)%"' ]] ;;
            http_client.timeout) [[ "$val" == "10" ]] ;;
            sram.allowed_attributes) [[ "$val" == *'dezi:login"'* && "$val" == *'dezi:dezi-nummer"'* ]] ;;
        esac && ok "$param = $val" || bad "$param = ${val:-<unreadable>}"
    done
    (cd "${ENGINE_CODE_PATH}" && APP_ENV=dev APP_DEBUG=true APP_SECRET=secret \
        php -d variables_order=EGPCS bin/console lint:container --env=dev >/dev/null 2>&1) \
        && ok "EngineBlock dev container lints (service argument types)" || bad "EngineBlock lint:container failed"
else
    miss "host PHP or EngineBlock vendor/ unavailable; EngineBlock parameters not compiled"
fi

section "Compose model (docker compose config; nothing is created)"
if err=$(compose --profile jip config --quiet 2>&1 >/dev/null); then
    ok "compose files render (devconf core + engine override + JIP overlay)"
    images=$(compose --profile jip config --images 2>/dev/null | sort -u)
    grep -q 'openconext-basecontainers/php85-apache2-node24' <<<"$images" \
        && ok "engine uses the development override image (EngineBlock ${ENGINE_TAG} source mounted)" \
        || bad "engine does not use the development override image"
    for img in $(grep -E 'openconext-manage/manage-(gui|server):' <<<"$images"); do
        v=${img##*:}
        [[ "$(printf '9.1.0\n%s\n' "$v" | sort -V | head -1)" == "9.1.0" ]] && ok "$img (>= 9.1.0)" || bad "$img (< 9.1.0)"
    done
    aliases=$(compose --profile jip config --format json 2>/dev/null | php -r '$c=json_decode(stream_get_contents(STDIN),true); echo implode(" ", $c["services"]["haproxy"]["networks"]["coreconextdev"]["aliases"] ?? []);')
    for h in jip mock-dezi jip-test-sp engine; do
        [[ " $aliases " == *" $h.dev.openconext.local "* ]] && ok "in-network alias $h.dev.openconext.local -> haproxy" \
            || bad "in-network alias $h.dev.openconext.local missing"
    done
    proxy_bindings=$(compose --profile jip config --format json 2>/dev/null | php -r '$c=json_decode(stream_get_contents(STDIN),true); foreach ($c["services"]["haproxy"]["ports"] ?? [] as $p) echo ($p["host_ip"] ?? "0.0.0.0")."\n";')
    if [[ -n "$proxy_bindings" ]] && ! grep -qvEx '127\.0\.0\.1|::1' <<<"$proxy_bindings"; then
        ok "HAProxy published on loopback only"
    else
        bad "HAProxy must publish on 127.0.0.1 or ::1 only (mock admin API has no authentication)"
    fi
    ports=$(compose config --format json 2>/dev/null | php -r '$c=json_decode(stream_get_contents(STDIN),true); foreach ($c["services"]["mariadb"]["ports"] ?? [] as $p) echo ($p["host_ip"] ?? "0.0.0.0").":".$p["published"]." ";')
    [[ "$ports" != *":3306 "* ]] && ok "mariadb published on ${ports% } (not 3306)" || bad "mariadb still publishes host port 3306"
else
    bad "compose config failed: $(head -3 <<<"$err")"
    images=""
fi

section "Container images present locally (pulling is not done by this script)"
for img in $images; do
    docker image inspect "$img" >/dev/null 2>&1 && ok "$img" || miss "image $img"
done

section "TLS certificate and trust"
pem="${DEVCONF_CORE_DIR}/haproxy/haproxy.pem"
if [[ -f "${DEV_CA_CERT}" && -f "$pem" ]]; then
    leaf=$(openssl x509 -in "$pem")
    for h in "${JIP_HOSTNAMES[@]}"; do
        openssl verify -CAfile "${DEV_CA_CERT}" -verify_hostname "$h" <(echo "$leaf") >/dev/null 2>&1 \
            && ok "certificate valid for $h" || bad "certificate not valid for $h"
    done
    end=$(openssl x509 -in "$pem" -noout -enddate | cut -d= -f2)
    openssl x509 -in "$pem" -noout -checkend $((30 * 86400)) >/dev/null \
        && ok "certificate expires ${end}" || bad "certificate expires within 30 days (${end}); delete core/haproxy/haproxy.{crt,pem} and re-run setup"
else
    miss "dev CA / HAProxy certificate: run devenv/bin/setup.sh"
fi
if [[ -f "${DEV_CA_CERT}" ]] && openssl verify -CApath /etc/ssl/certs "${DEV_CA_CERT}" >/dev/null 2>&1; then
    ok "dev CA trusted by the host system store"
else
    miss "dev CA not in the host system store (optional; host checks use --cacert, browsers need a manual import)"
fi

section "Host name resolution (/etc/hosts)"
for h in "${JIP_HOSTNAMES[@]}"; do
    addr=$(getent hosts "$h" | awk '{print $1}' | head -1)
    case "$addr" in
        127.0.0.1|::1) ok "$h -> $addr" ;;
        "") miss "$h does not resolve (add it to /etc/hosts, needs root)" ;;
        *) bad "$h -> $addr (expected 127.0.0.1 or ::1)" ;;
    esac
done

section "Running services"
running=$(compose ps --status running --services 2>/dev/null | sort)
for svc in haproxy mariadb mongo engine managegui manageserver mujina-idp jip mock-dezi jip-test-sp; do
    grep -qx "$svc" <<<"$running" && ok "$svc running" || miss "$svc not running"
done
if grep -qx jip <<<"$running"; then
    compose exec -T -u "${JIP_CONTAINER_WEB_UID}" jip php bin/console jip:config:validate --no-ansi >/dev/null 2>&1 \
        && ok "jip: startup checks pass as the web-server user" || bad "jip: startup checks fail as the web-server user"
    compose exec -T -u "${JIP_CONTAINER_WEB_UID}" jip curl -fsS -o /dev/null http://localhost/health \
        && ok "jip: /health is UP inside the container" || bad "jip: /health is not UP inside the container"
fi
if grep -qx mock-dezi <<<"$running"; then
    compose exec -T -u "${JIP_CONTAINER_WEB_UID}" mock-dezi curl -fsS -o /dev/null http://localhost/health \
        && ok "mock-dezi: /health is UP inside the container" || bad "mock-dezi: /health is not UP inside the container"
fi

section "Reachability from the host (https via HAProxy, verified against the dev CA)"
for h in "${JIP_HOSTNAMES[@]}"; do
    getent hosts "$h" >/dev/null || { miss "https://$h/ (name does not resolve)"; continue; }
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 --cacert "${DEV_CA_CERT}" "https://$h/" 2>&1)
    case "$code" in
        2??|3??|401|403|404) ok "https://$h/ -> HTTP $code" ;;
        503) miss "https://$h/ -> HTTP 503 (HAProxy up, backend not running)" ;;
        *) miss "https://$h/ unreachable (${code})" ;;
    esac
done

section "Reachability inside the compose network"
probe() { # <from service> <url>
    grep -qx "$1" <<<"$running" || { miss "$1 -> $2 (needs $1 running)"; return; }
    code=$(compose exec -T "$1" curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$2" 2>&1)
    [[ "$code" =~ ^[2-4][0-9][0-9]$ && "$code" != 404 ]] && ok "$1 -> $2 (HTTP $code, TLS verified)" || miss "$1 -> $2 (${code})"
}
probe engine https://jip.dev.openconext.local/health
probe jip https://mock-dezi.dev.openconext.local/.well-known/openid-configuration

printf '\nSummary: %d FAIL, %d MISSING\n' "$fails" "$missing"
[[ $fails -eq 0 ]]
