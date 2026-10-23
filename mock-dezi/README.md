# Mock DEZI provider

A local OpenID Connect provider that imitates DEZI (the CIBG's "Ontkoppelpunt") for the
JointIdentityProvider (JIP) proof of concept
([design](../docs/2026-10-05-high-level-design-dezi-connector.md), §11 and §14–§18). JIP is its client.
It serves synthetic people and statements, and every protocol failure that JIP must handle can be
selected per login or per endpoint.

**Mock only.** Nothing here is DEZI data or a confirmed DEZI message. The mock never runs outside
local development, and none of its values moves into JIP's acceptance or production configuration
(design §16, §17). Its admin API has no authentication, so it must never be reachable from outside
the development machine.

## Endpoints

All addresses are relative to the issuer `https://mock-dezi.dev.openconext.local` (HAProxy terminates
TLS; the container serves plain HTTP behind it).

| Endpoint | Path | Notes |
| --- | --- | --- |
| Discovery | `GET /.well-known/openid-configuration` | Shaped like DEZI acceptance discovery: code flow, `query`, `openid`, `pairwise`, `RS256`, PKCE `S256`, `token_endpoint_auth_methods_supported: [none, private_key_jwt]` |
| Authorisation | `GET /authorize` | Shows the simulated eIDAS-high login, then profile selection when the person has more than one profile |
| Token | `POST /token` | `private_key_jwt` (or `none` for a client registered that way), single-use code, PKCE `S256` |
| Key set, ID token | `GET /openid/connect/jwks.json` | The ID-token key only |
| Key set, envelope | `GET /envelope/jwks.json` | The envelope key only (mock address) |
| Key set, statement | `GET /dezi/jwks.json` | The statement key only |
| UserInfo | `GET` or `POST /userinfo` | `Authorization: Bearer`; a JWE (`RSA-OAEP`, `A256CBC-HS512`) around the signed envelope, which carries the sealed statement |
| Status check | `GET /status/v1/verklaring/{verklaring_id}` | The specification's path; `200` with `actief`, another status, `404` for an unknown statement, or a selected failure |
| Statement links | `/statement-link/{status,revocatie}/{id}` | Where `status_uri` and `revocatie_controle_uri` in the statement point. JIP must never call them (§15); calls are counted in `GET /mock/state` and answered `410` |
| Admin | `/mock/...` | Scenario selection and reset, below |
| Overview | `GET /` | People, profiles and scenarios in a page |
| Health | `GET /health` | `200 UP` when configuration, fixtures and keys are usable |

These match JIP's [config/jip/mock.yaml](../jip/config/jip/mock.yaml): issuer, the three key
addresses, the expected envelope and statement issuers, the assurance values, the status address
template and client `jip-mock-ggd`. The mock's envelope audiences deliberately differ from the
client IDs: `jip-mock-ggd-envelope` and `jip-mock-ggd-none-envelope`. JIP's mock configuration sets
them explicitly as the expected envelope audiences (`provider.envelope.audiences`).

## Initialization

Requirements: PHP 8.5 with `openssl`, Composer 2. The mock signs and encrypts directly with OpenSSL.

```bash
cd mock-dezi
composer install
bin/init-keys                          # the mock's signing keys under keys/ (git-ignored)
../jip/bin/init-mock-keys              # JIP's client keys; the mock reads only the two certificates
bin/console mock-dezi:reset --check    # configuration, fixtures and keys usable; state kept
```

`devenv/bin/setup.sh` runs `bin/init-keys` as well and gives the container's web-server user
(`www-data`, uid 33) ACL access to `keys/` and `var/`, as it does for JIP. `devenv/bin/check.sh`
verifies it.

| Variable | Default (`.env`) | Meaning |
| --- | --- | --- |
| `MOCK_DEZI_CONFIG_FILE` | `config/mock-dezi.yaml` | Provider settings and client registrations |
| `MOCK_DEZI_FIXTURES_FILE` | `fixtures/profiles.yaml` | The synthetic people and profiles |
| `MOCK_DEZI_CLIENT_KEYS_DIR` | `../jip/keys/mock` | Where the registered client certificates are read (`/etc/mock-dezi/client-keys` in the container) |
| `MOCK_DEZI_KEYS_DIR` | `keys` | The mock's own private keys |
| `MOCK_DEZI_STATE_FILE` | `var/mock-dezi/state.json` | Logins, codes, tokens, used assertion IDs and selections |

## Running

In devconf:

```bash
devenv/bin/compose.sh up -d --wait mock-dezi
```

The container entrypoint ([devenv/mock-dezi/entrypoint.sh](../devenv/mock-dezi/entrypoint.sh)) clears
the cache as `www-data`, **resets the mock's state**, and starts Apache only when the configuration,
fixtures and keys are usable. JIP reaches the mock as `https://mock-dezi.dev.openconext.local` through
HAProxy, with the dev CA.

On the host, for a quick look (plain HTTP, so a browser does not keep the `Secure` session cookie):

```bash
APP_ENV=dev php -S 127.0.0.1:8001 -t public public/index.php
```

PHP's built-in server handles one request at a time; a `timeout` selection blocks it for
`timeout_delay_seconds`.

## The login

`GET /authorize` validates the request (registered `client_id` and exact `redirect_uri`, otherwise
an error page and no redirect; then `response_type=code`, `response_mode` `query`, `scope` exactly
`openid`, non-empty `state` and `nonce`, `code_challenge_method=S256` with a 43-character challenge,
`prompt`, `max_age`) and answers errors at the callback with `state`.

**Fresh authentication.** With `prompt=login` or `max_age=0` the mock always shows the login page,
and `auth_time` is the moment the form is submitted, so it lies after JIP's attempt start. The
mock also keeps its own DEZI session (cookie `mock_dezi_session`, `Secure`, `HttpOnly`,
`SameSite=Lax`). Without `prompt=login`, it reuses that session within `max_age` and returns the
session's earlier `auth_time`, as a real provider would; JIP must refuse that. `prompt=none` without
a session answers `login_required`.

**Automating the login.** A test that plays the browser submits the login page form:

```text
POST /authorize/login     request_id=<from the page>  person=<person id>  scenario=<name, empty = default>  action=login|cancel
POST /authorize/profile   request_id=<same>           profile=<profile id>                                  action=continue|cancel
```

The profile form appears only for a person with more than one profile. The answer is a `302` to
the client's `redirect_uri` with `code` and `state`, or `error` and `state`.

**Token endpoint.** For a `private_key_jwt` client the mock requires `client_id`,
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a compact JWS
`client_assertion` with: `alg` `RS256`; header `x5t#S256` naming one of the client's registered
signing certificates (two may be registered during a replacement); a valid signature; `iss` = `sub`
= client ID; `aud` = the token endpoint (a string, or a list with only that value); `iat` and `exp`
as integers; `exp` not passed (60 s skew); `exp - iat` at most
`max_client_assertion_lifetime_seconds`; and a `jti` never seen before. A failure answers `401
invalid_client` with the reason in `error_description`. A `none` client must send no assertion.
Then the code must exist, be unused and unexpired, belong to the client and `redirect_uri`, and
match the `code_verifier` (S256). Once the client is authenticated, the request consumes the code,
also when the grant then fails, for example on a wrong verifier.

**Messages.** The ID token is `RS256` with the ID-token key: `iss`, pairwise `sub`, `aud` (client
ID), `iat`, `exp`, `auth_time`, `nonce`. UserInfo is a JWE to the client's registered encryption
certificate with header `kid` (`encryption_kid`, or the RFC 7638 thumbprint of the certificate's
key). Inside: the envelope (`iss`, `aud`, `iat`, `exp`, `loa_authn`, `verklaring_id`, and the
statement under `verklaring`), signed with the envelope key. The statement (`jti`, `iss`, `nbf`,
`exp`, `json_schema`, `dezi_nummer`, `voorletters`, `voorvoegsel`, `achternaam`, `abonnee_nummer`,
`abonnee_naam`, `rol_code`, `rol_naam`, `rol_code_bron`, `loa_dezi`, `verklaring_id`, `status_uri`,
`revocatie_controle_uri`) is sealed with the statement key, header `jku` = the statement key address.

## Fixtures (PROVISIONAL, synthetic)

[fixtures/profiles.yaml](fixtures/profiles.yaml). Each profile has a fixed `verklaring_id`, because
the register may reuse a statement across logins (§15).

| Person | DEZI number | Profiles | Use |
| --- | --- | --- | --- |
| `anna` | `900000001` | one, role `01.000` | The match case: an organisation account carrying `900000001` |
| `bram` | `900000002` | two (`1.015` at `90000001`, `01.000` at `90000002`) | Profile selection; `voorvoegsel` `van der` |
| `carla` | `900000003` | one, no role | No `rol_code`, `rol_naam` or `rol_code_bron` claim |
| `dirk` | `900000004` | one, role `00.000` | Released unchanged as a string |
| `eva` | `900000005` | one, register status revoked | Status check answers `ingetrokken` |
| `frank` | `900000006` | one, role `01.000` | The different identity: log in at the organisation as an account with `900000001`, at the mock as `frank` |

Organisation accounts are configured in [devenv/mujina/accounts.json](../devenv/mujina/accounts.json);
see the [account table](../devenv/README.md#local-integration-design-68-17) for binding inputs and
expected outcomes. They carry these numbers in
`urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer`.

## Selecting scenarios

There are three independent selections. `GET /mock/scenarios` lists every value with its
description, and `GET /mock/state` shows the current selections.

**1. Per login: the scenario.** Chosen on the login page (or the `scenario` form field). It travels
with the code and the access token and affects only that login. `success` changes nothing. Every
other scenario changes one thing that JIP must refuse, except the two marked *accepted*.

| Step | Scenarios |
| --- | --- |
| Authorisation response | `cancel` (`error=access_denied`), `authorize_error` (`server_error`), `callback_wrong_state`, `stale_auth_time`, `future_auth_time` |
| Token response | `token_server_error`, `token_invalid_client`, `token_invalid_grant`, `token_type_not_bearer`, `token_without_id_token`, `token_without_access_token` |
| ID token | `id_token_bad_signature`, `id_token_unknown_kid`, `id_token_signed_with_statement_key`, `id_token_alg_none`, `id_token_wrong_issuer`, `id_token_wrong_audience`, `id_token_extra_audience`, `id_token_wrong_nonce`, `id_token_expired`, `id_token_without_auth_time`, `id_token_without_sub` |
| UserInfo (JWE) | `userinfo_server_error`, `userinfo_not_encrypted`, `userinfo_wrong_key_algorithm` (`RSA-OAEP-256`), `userinfo_wrong_content_encryption` (`A256GCM`), `userinfo_unregistered_key`, `userinfo_unknown_kid` (*accepted*: the registered key still decrypts) |
| Envelope | `envelope_bad_signature`, `envelope_unknown_kid`, `envelope_signed_with_id_token_key`, `envelope_jku_other_address`, `envelope_wrong_issuer`, `envelope_wrong_audience`, `envelope_expired`, `envelope_wrong_loa`, `envelope_without_verklaring_id`, `envelope_with_sub` (*accepted*: equal to the ID token's `sub`), `envelope_sub_mismatch` |
| Statement | `statement_bad_signature`, `statement_unknown_kid`, `statement_signed_with_id_token_key`, `statement_jku_other_address`, `statement_wrong_issuer`, `statement_expired`, `statement_not_yet_valid`, `statement_time_as_string`, `statement_verklaring_id_mismatch`, `statement_verklaring_id_not_uuid`, `statement_wrong_loa`, `statement_numeric_dezi_nummer`, `statement_empty_abonnee_nummer`, `statement_dezi_nummer_null`, `statement_rol_code_null`, `statement_voorvoegsel_string_null` |
| Status check | `status_revoked`, `status_other_status`, `status_not_found`, `status_bad_request`, `status_server_error`, `status_timeout`, `status_redirect`, `status_invalid_body`, `status_wrong_id` |

"Bad signature" signs with an unpublished key under the published `kid`; "unknown kid" uses an
unpublished key and `kid` (JIP refetches once, then refuses); "signed with another key" uses another
message type's published key, so it verifies only against the wrong key address. Each status
scenario issues a fresh `verklaring_id` registered with that behaviour, so no other login is affected.

The default for the page and for a form without `scenario`:

```bash
curl -X PUT -H 'Content-Type: application/json' -d '{"scenario":"cancel"}' \
     --cacert devenv/certs/openconext-dev-ca.crt https://mock-dezi.dev.openconext.local/mock/default-scenario
```

**2. Per endpoint: availability.** Applies to every request until changed. Endpoints: `discovery`,
`jwks_id_token`, `jwks_envelope`, `jwks_statement`, `token`, `userinfo`, `status`. Modes for all:
`available`, `server_error` (500), `unavailable` (503), `timeout` (normal answer after
`timeout_delay_seconds`, 12 s by default, above JIP's 5 s status timeout), `redirect` (key sets
redirect to another message type's approved key address; other endpoints redirect once to the
same URL with `?redirected=1` and then answer normally; POST uses `307` to preserve its method
and body, GET uses `302`), `invalid_body`. Discovery also:
`auth_methods_none_only`, `without_auth_methods`, `wrong_issuer`, `wrong_jwks_uri`. Key sets also:
`empty_key_set`.

```bash
curl -X PUT -H 'Content-Type: application/json' -d '{"mode":"timeout"}' .../mock/endpoints/status
```

**3. Per statement: the register status.** For revocation after login, renewal at delivery, or any
statement ID: `active`, `revoked`, `other_status`, `not_found`, `bad_request`, `server_error`,
`timeout`, `redirect` (`302` to the same URL with `?redirected=1`, which answers active),
`invalid_body`, `wrong_id`.

```bash
curl -X PUT -H 'Content-Type: application/json' -d '{"behaviour":"revoked"}' \
     .../mock/statements/d3e2a1c0-0001-4000-8000-000000000001
```

Admin changes require `Content-Type: application/json`; otherwise `415`.

## Reset

| What | How |
| --- | --- |
| State (logins, sessions, codes, tokens, used `jti` values, default scenario, endpoint modes, statement behaviours, link counters) | `curl -X POST -H 'Content-Type: application/json' .../mock/reset`, `bin/console mock-dezi:reset`, or restart the container |
| Signing keys | Delete `keys/` and run `bin/init-keys` (then `devenv/bin/setup.sh` for the ACLs). JIP's key cache then needs its refetch rule or a restart |
| Client certificates | Follow JIP's key procedure; the mock reads the files named in `config/mock-dezi.yaml` on every request |

## PROVISIONAL assumptions (not confirmed by the CIBG)

Every item below is a mock choice that stays in this application and in JIP's `mock.yaml`. The
CIBG's answers (design §10) replace them; none is evidence of DEZI's behaviour.

| Item | Mock choice | Source or open question |
| --- | --- | --- |
| Client authentication | Discovery lists `none` and `private_key_jwt`; the mock verifies `private_key_jwt` | Acceptance discovery (12 October 2026); v0.7 shows `none` only. Whether DEZI accepts it is open (§10) |
| Assertion contents | `RS256`, `x5t#S256` required, `aud` = token endpoint, lifetime ≤ 300 s, `jti` single use, 60 s skew | The design's §14 contents; DEZI's requirements are open (§10) |
| Signing key registration | Registered as certificates next to the encryption certificate | Form DEZI01.1 has no field for it (§10) |
| Envelope key address | `/envelope/jwks.json`, its own key | DEZI's envelope key is described in conflicting ways (§16) |
| Issuers | `auth.mock-dezi.dev.openconext.local` (envelope), `abonnee.mock-dezi.dev.openconext.local` (statement) | Shaped like v0.7's `auth.dezi.nl` and `abonnee.dezi.nl` (§16) |
| Envelope audience | `envelope_audience` per client, not the client ID | Open (§14) |
| Envelope `sub` | Absent | As v0.7; scenarios add one (§14) |
| Statement claim in the envelope | `verklaring` | Not named in the design; the CIBG's example messages decide (§10) |
| `jku` | On the statement, not on the envelope | Open (§14, §16) |
| Assurance values | `http://eidas.europa.eu/LoA/high` (`loa_authn`), `http://eidas.europe.eu/LoA/high` (`loa_dezi`) | v0.7 example values (§16) |
| Status answer | `{"verklaringId", "status": "actief"}`; revoked `ingetrokken` with `revocatieTijdstip`; other status `mock-andere-status`; `404` `application/problem+json` | v0.7 example names; `404` observed on acceptance; other values invented (§10) |
| Error codes at the callback | `access_denied` (cancel), `server_error` | RFC 6749 codes; DEZI's are not known |
| Message lifetimes | ID token and envelope 300 s, statement 24 h, code 60 s | Not known |
| UserInfo content type | `application/jwt` | Not known |
| JWE `kid` | Configured value, or the RFC 7638 thumbprint | v0.7 shows a `kid`; its value is not known |
| Identifier formats | DEZI and subscriber numbers as digit strings, role codes `01.000`, `1.015`, `00.000` | §4, §16; the exact formats are open (§10) |
| Profile without a role | Role claims omitted | Open (§16); `statement_rol_code_null` covers the null shape |
| `max_age` | Supported (`0` forces a fresh login) | DEZI support is open (§10) |

## Not implemented

- The revocation list (`status_check_with_list`, design §15): optional, and JIP's POC uses the status
  check alone.
- Logout, refresh tokens, the `claims` parameter (accepted and ignored), request objects.
- TLS 1.3 enforcement on the server side: HAProxy terminates TLS (devenv README).

## Quality checks

```bash
composer check        # lint:yaml, lint:container, phpcs, phpstan (level max), phpunit
```

The tests play JIP: they build every request and check the answers with web-token (the library JIP
uses) and with plain OpenSSL for the JWE, independently of the mock's own code.
