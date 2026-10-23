#!/usr/bin/env bash
# Repeatable verification of the JointIdentityProvider (JIP) POC against the running local stack
# (design §11, §18). Every case states its expected outcome; the script exits 1 when any case differs.
#
#   devenv/bin/verify-poc.sh            all cases (the key-refetch and renewal cases each wait about a minute)
#   devenv/bin/verify-poc.sh --quick    without sbs-flow.py's withdrawal and renewal cases
#
# 1. Browser logins through test SP -> EngineBlock -> Mujina -> JIP -> mock DEZI provider -> test SP
#    (login-flow.py): identity cases and every per-login mock DEZI scenario.
# 2. Provider availability: discovery failure modes and an unanswered key refetch.
# 3. EngineBlock-side transaction cases without EngineBlock (sbs-flow.py).
#
# Requires the running stack and persisted Mujina accounts (devenv/README.md). Resets the mock DEZI
# provider's state and clears JIP's provider cache (public metadata and keys only). Changes nothing in
# Manage or EngineBlock. `--quick` skips the case that edits jip/config/jip/mock.yaml.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}" || exit 2
JIP_CONTAINER="${JIP_CONTAINER:-core-jip-1}"
MOCK=https://mock-dezi.dev.openconext.local
CA=devenv/certs/openconext-dev-ca.crt
passed=0
failed=0

mock() { # METHOD PATH [JSON]
    local body="${3:-}"
    [[ -z "${body}" ]] && body='{}'
    curl -sS -o /dev/null --fail --cacert "${CA}" -X "$1" -H 'Content-Type: application/json' -d "${body}" "${MOCK}$2"
}

clear_provider_cache() {
    docker exec -u www-data -w /var/www/html "${JIP_CONTAINER}" sh -c 'rm -rf "var/cache/${APP_ENV}/jip-provider"'
}

login() { # EXPECT RESTART ACCOUNT [login-flow options...]
    local expect="$1" restart="$2" account="$3"
    shift 3
    local options=(--expect "${expect}")
    [[ "${restart}" != - ]] && options+=(--restart "${restart}")
    local output
    if output="$(timeout 120 python3 devenv/bin/login-flow.py login "${account}" "$@" "${options[@]}" 2>&1)"; then
        passed=$((passed + 1))
        printf '  PASS  %-60s %s\n' "${account} $*" "${expect}"
    else
        failed=$((failed + 1))
        printf '  FAIL  %-60s expected %s (restart %s)\n' "${account} $*" "${expect}" "${restart}"
        printf '%s\n' "${output}" | grep -v 'route:' | sed 's/^/        /'
    fi
}

scenario() { # SCENARIO EXPECT RESTART
    login "$2" "$3" jip-anna --person anna --scenario "$1"
}

mock POST /mock/reset || { echo 'the mock DEZI provider is not reachable; start the stack first' >&2; exit 2; }

echo 'Identity cases (design §4, §6, §7, §16)'
login dezi - jip-anna --person anna
login organisation - jip-nonumber
login organisation - jip-empty
login organisation - jip-spaces
login refused - jip-bram --person bram --profile bram-ggd-noord
login refused - jip-bram --person bram --profile bram-ggd-zuid
login refused - jip-carla --person carla
login refused - jip-dirk --person dirk
login jip-error:statement_not_active no jip-eva --person eva
login jip-error:binding_mismatch no jip-anna --person frank
login jip-error:malformed_binding no jip-multi
login jip-error:reserved_attribute no jip-forged
login jip-error:provider_cancelled yes jip-anna --person anna --dezi-action cancel

echo 'Mock DEZI scenarios per login (design §14-§16)'
# Restart expectations follow jip/README.md and the documented handover deviations from §§13/18.
while read -r name expect restart; do
    [[ -z "${name}" || "${name}" == \#* ]] && continue
    scenario "${name}" "${expect}" "${restart}"
done <<'EOF'
success                             dezi                                     -
authorize_error                     jip-error:provider_error                 yes
callback_wrong_state                jip-error:link_not_valid                 no
stale_auth_time                     jip-error:id_token_invalid               no
future_auth_time                    jip-error:id_token_invalid               no
token_server_error                  jip-error:token_request_unavailable      yes
token_invalid_client                jip-error:client_authentication_refused  no
token_invalid_grant                 jip-error:token_request_refused          no
token_type_not_bearer               jip-error:token_response_invalid         no
token_without_id_token              jip-error:token_response_invalid         no
token_without_access_token          jip-error:token_response_invalid         no
id_token_bad_signature              jip-error:id_token_invalid               no
id_token_unknown_kid                jip-error:unknown_key                    no
id_token_signed_with_statement_key  jip-error:unknown_key                    no
id_token_alg_none                   jip-error:id_token_invalid               no
id_token_wrong_issuer               jip-error:id_token_invalid               no
id_token_wrong_audience             jip-error:id_token_invalid               no
id_token_extra_audience             jip-error:id_token_invalid               no
id_token_wrong_nonce                jip-error:id_token_invalid               no
id_token_expired                    jip-error:id_token_invalid               no
id_token_without_auth_time          jip-error:id_token_invalid               no
id_token_without_sub                jip-error:id_token_invalid               no
userinfo_server_error               jip-error:userinfo_unavailable           yes
userinfo_not_encrypted              jip-error:userinfo_invalid               no
userinfo_wrong_key_algorithm        jip-error:userinfo_invalid               no
userinfo_wrong_content_encryption   jip-error:userinfo_invalid               no
userinfo_unregistered_key           jip-error:userinfo_not_decrypted         no
userinfo_unknown_kid                dezi                                     -
envelope_bad_signature              jip-error:envelope_invalid               no
envelope_unknown_kid                jip-error:unknown_key                    no
envelope_signed_with_id_token_key   jip-error:unknown_key                    no
envelope_jku_other_address          jip-error:envelope_invalid               no
envelope_wrong_issuer               jip-error:envelope_invalid               no
envelope_wrong_audience             jip-error:envelope_invalid               no
envelope_expired                    jip-error:envelope_invalid               no
envelope_wrong_loa                  jip-error:envelope_invalid               no
envelope_without_verklaring_id      jip-error:envelope_invalid               no
envelope_with_sub                   dezi                                     -
envelope_sub_mismatch               jip-error:envelope_invalid               no
statement_bad_signature             jip-error:statement_invalid              no
statement_unknown_kid               jip-error:unknown_key                    no
statement_signed_with_id_token_key  jip-error:unknown_key                    no
statement_jku_other_address         jip-error:statement_invalid              no
statement_wrong_issuer              jip-error:statement_invalid              no
statement_expired                   jip-error:statement_invalid              no
statement_not_yet_valid             jip-error:statement_invalid              no
statement_time_as_string            jip-error:statement_invalid              no
statement_verklaring_id_mismatch    jip-error:statement_invalid              no
statement_verklaring_id_not_uuid    jip-error:statement_invalid              no
statement_wrong_loa                 jip-error:statement_invalid              no
statement_numeric_dezi_nummer       jip-error:statement_invalid              no
statement_empty_abonnee_nummer      jip-error:statement_invalid              no
statement_dezi_nummer_null          jip-error:statement_invalid              no
statement_rol_code_null             jip-error:statement_invalid              no
statement_voorvoegsel_string_null   jip-error:statement_invalid              no
status_revoked                      jip-error:statement_not_active           no
status_other_status                 jip-error:statement_not_active           no
status_wrong_id                     jip-error:statement_not_active           no
status_not_found                    jip-error:statement_unknown              no
status_bad_request                  jip-error:status_request_refused         no
status_server_error                 jip-error:status_check_unavailable       yes
status_timeout                      jip-error:status_check_unavailable       yes
status_redirect                     jip-error:status_check_unavailable       yes
status_invalid_body                 jip-error:status_check_unavailable       yes
EOF

echo 'Provider availability (design §14): discovery, then an unanswered key refetch'
while read -r mode expect restart; do
    clear_provider_cache
    mock PUT /mock/endpoints/discovery "{\"mode\":\"${mode}\"}"
    login "${expect}" "${restart}" jip-anna --person anna
# Restart expectations follow jip/README.md and the documented handover deviations from §§13/18.
done <<'EOF'
wrong_issuer            jip-error:discovery_invalid                    no
wrong_jwks_uri          jip-error:discovery_invalid                    no
auth_methods_none_only  jip-error:authentication_method_not_supported  no
without_auth_methods    jip-error:authentication_method_not_supported  no
unavailable             jip-error:discovery_unavailable                yes
server_error            jip-error:discovery_unavailable                yes
redirect                jip-error:discovery_unavailable                yes
invalid_body            jip-error:discovery_unavailable                yes
EOF
mock POST /mock/reset
clear_provider_cache
login dezi - jip-anna --person anna
echo '  ....  waiting 61 s: an unknown kid triggers a refetch only provider.key_refetch_min_interval_seconds after the last fetch'
sleep 61
mock PUT /mock/endpoints/jwks_statement '{"mode":"redirect"}'
scenario statement_unknown_kid jip-error:key_fetch_unavailable yes
login dezi - jip-anna --person anna    # the kept statement keys still serve a known kid
mock POST /mock/reset

echo 'EngineBlock-side transaction cases (design §12, §13, §15)'
cases=()
[[ "${1:-}" == --quick ]] && cases=(premature-repeat concurrent two-tabs callback-replay skip start-input organisation
    authentication fresh-decision)
if timeout 600 python3 devenv/bin/sbs-flow.py run "${cases[@]}"; then
    passed=$((passed + 1))
else
    failed=$((failed + 1))
fi

printf '\n%d passed, %d failed (sbs-flow.py counts as one)\n' "${passed}" "${failed}"
[[ "${failed}" -eq 0 ]]
