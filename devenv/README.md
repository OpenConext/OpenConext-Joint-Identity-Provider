# JointIdentityProvider (JIP) POC: local environment and library choice

The development environment for the proof of concept (design §10, §11, §19). It sets up
OpenConext-devconf with EngineBlock 7.2.1 and Manage 9.1.0 or later, and records the OIDC/JOSE library choice. The
JIP application itself is in `../jip` (see [jip/README.md](../jip/README.md)).

**Naming.** JIP is the module the design calls the "DEZI connector". "DEZI" remains only for the
external provider (CIBG), its messages and attribute names, and the mock that imitates it.

Setup, initialization, startup, shutdown, reset, demonstration and repeatable verification are
summarised in the [JIP POC handover](../docs/jip-poc-handover.md).

## Running the current implementation

The POC services JIP, the mock DEZI provider
(see [mock-dezi/README.md](../mock-dezi/README.md)) and the JIP test SP run next to HAProxy, MariaDB,
MongoDB, mailcatcher, EngineBlock, Manage GUI/server, Mujina IdP and Profile. The complete login
(test SP → EngineBlock → Mujina → EngineBlock → JIP → mock DEZI → JIP → EngineBlock → test SP) runs
locally; see [Local integration](#local-integration-design-68-17).

From the repository root, start or resume the services:

```bash
devenv/bin/compose.sh up -d --wait
devenv/bin/compose.sh up -d --wait jip mock-dezi jip-test-sp
devenv/bin/compose.sh ps
```

Naming `jip`, `mock-dezi` or `jip-test-sp` explicitly starts that application from the `jip` profile;
`COMPOSE_PROFILES=jip` in `.env` starts all three with the core.

Once the host names and CA trust below are configured, open:

- JIP readiness: https://jip.dev.openconext.local/health (login starts with EngineBlock's hand-off;
  JIP redirects to the mock provider's login page).
- Mock DEZI provider overview, once its container runs: https://mock-dezi.dev.openconext.local/
- Manage: https://manage.dev.openconext.local/
- EngineBlock: https://engine.dev.openconext.local/
- Mujina IdP: https://mujina-idp.dev.openconext.local/
- Profile: https://profile.dev.openconext.local/
- Captured development email: http://localhost:1080/

Stop the stack while preserving its database volumes:

```bash
devenv/bin/compose.sh --profile jip stop
```

Run `devenv/bin/check.sh` for diagnostics. An exit code of zero means no failed checks, and does not
mean there are no missing prerequisites.

## Layout

| Path | Purpose |
| --- | --- |
| `env.dist` | Pinned versions and settings; `bin/setup.sh` copies it to `.env` and generates the SBS API token |
| `bin/setup.sh` | Idempotent preparation without containers: checkouts, EngineBlock `composer install`, `.env`, dev CA, HAProxy config, EngineBlock drop-in, JIP mock keys and the container user's ACLs on `jip/keys` and `jip/var`, the mock DEZI provider's keys and the same ACLs on `mock-dezi/keys` and `mock-dezi/var` |
| `bin/compose.sh` | `docker compose` with devconf core + devconf's EngineBlock development override + `compose/jip.override.yml` |
| `bin/check.sh` | Read-only verification. `OK` = verified, `MISSING` = prerequisite not supplied, `FAIL` = wrong configuration (exit 1) |
| `compose/jip.override.yml` | HAProxy aliases and routes, Manage pin, MariaDB port, API token for EngineBlock, the three POC services (profile `jip`) |
| `engine/zz_jip_sbs.yaml` | EngineBlock SBS settings (§17), installed into `config/packages/dev/` of the EngineBlock checkout |
| `jip/appconf.conf` | Apache virtual host for JIP (document root `public/`, `Authorization` passed to PHP, path-only access log without headers) |
| `jip/entrypoint.sh` | Entrypoint of the `jip` container: imports the dev CA, then starts Apache only when `jip:config:validate` passes as `www-data`. It replaces the base image entrypoint, which clears the cache as root and makes `var/cache` and `var/log` mode 1777 |
| `mock-dezi/appconf.conf`, `mock-dezi/entrypoint.sh` | The same for the `mock-dezi` container: document root `public/`; the entrypoint resets the mock's state and starts Apache only when `mock-dezi:reset` passes as `www-data`. Only JIP's two public client certificates are mounted read-only; its private keys are not mounted |
| `bin/_haproxy.sh` | Shared HAProxy renderer and logging guard used by setup and diagnostics; rejects remaining `httplog` directives and unapproved log formats before publishing a generated configuration |
| `tests/haproxy-logging.sh` | Container-free regression checks for proxy logging; run with `bash devenv/tests/haproxy-logging.sh` from the repository root |
| `test-sp/appconf.conf` | Apache virtual host for the test SP (`../test-sp`), with the same path-only access log. Compose starts Apache directly, without changing ownership or permissions in the checkout |
| `manage/jip-test-sp.json` | Manage entity of the test SP: `coin:collab_enabled`, explicit release policy, organisation connection |
| `bin/manage.php` | `apply` writes the test SP to Manage and pushes to EngineBlock; `audit` checks the §17 operator checklist read-only |
| `bin/_manage.php`, `tests/ManagePushTest.php` | Push error handling and regression tests; only the exact known unavailable OIDC backend response is tolerated |
| `mujina/accounts.json` | Synthetic Mujina accounts with valid, absent, empty, whitespace, multiple and forged binding input |
| `bin/login-flow.py` | Scripted browser for the complete login; prints the test SP's decision or JIP's error page; `--expect` and `--restart` assert the outcome |
| `bin/sbs-flow.py` | Plays EngineBlock's `/authz` and `/attributes` calls and a browser against the running JIP and mock DEZI provider: premature, repeated and concurrent result calls, two tabs, replay, organisation refusal and withdrawal, renewal |
| `bin/verify-poc.sh` | Repeatable POC verification against the running stack: every login and mock DEZI scenario with its expected outcome, provider availability, and `sbs-flow.py` |
| `haproxy/jip-backends.*` | Added to devconf's HAProxy config; the result is written to `haproxy/generated/` |
| `libcheck/` | Executable check of the library choice (`verify.php`) |
| `upstream/` | devconf and EngineBlock checkouts (git-ignored) |

## Versions

| Component | Version | Source |
| --- | --- | --- |
| OpenConext-devconf | `main` at `2b6f5eb4` (12 October 2026) | `env.dist` |
| EngineBlock | `7.2.1` (`9ce5c9f9`), source mounted through devconf's `core/engine/docker-compose.override.yml`, image `php85-apache2-node24` | `env.dist`; the tag's `AuthzRequest` sends `attributes` (§9 item 2) and its `composer.json` requires PHP `^8.5` and Symfony `^7.4` |
| Manage (gui and server) | `9.7.2` (≥ 9.1.0; schema has `coin:collab_enabled`) | `env.dist`, pinned in the overlay |
| Mujina IdP, HAProxy, MariaDB, Mongo | `9.0.1`, `haproxy28:latest`, `10.11`, `7` | devconf defaults |

## Host names, TLS and connectivity

All names are under `dev.openconext.local`. devconf's HAProxy serves them on host ports 80/443 with
its wildcard certificate `*.dev.openconext.local`. The issuing CA is name-constrained to that domain
and its private key is deleted after issuance (`core/scripts/create_dev_ca.sh`).

| Host name | Service | Backend |
| --- | --- | --- |
| `engine.dev.openconext.local`, `engine-api.…` | EngineBlock 7.2.1 | `engine:80` |
| `manage.dev.openconext.local` | Manage | `managegui:80` |
| `mujina-idp.dev.openconext.local` | organisation IdP | `mujina-idp:80` |
| `jip.dev.openconext.local` | JointIdentityProvider (JIP) | `jip:80` |
| `mock-dezi.dev.openconext.local` | mock DEZI provider | `mock-dezi:80` |
| `jip-test-sp.dev.openconext.local` | test SP | `jip-test-sp:80` |

- **Browser → services:** `/etc/hosts` maps the names to `127.0.0.1`/`::1`, and HAProxy routes them.
- **Server to server** (EngineBlock → JIP `/authz` and `/attributes`, JIP → mock DEZI): the names
  are network aliases of HAProxy on `coreconextdev`, so every call uses HTTPS with the same
  certificate.
- **Trust in containers:** EngineBlock gets `/config/haproxy/haproxy.crt` through devconf's
  `./:/config` mount and its base entrypoint imports it into the system store. JIP gets a dedicated
  certificate mount and imports it through its custom entrypoint. The test SP makes no
  server-to-server call and imports no dev CA: it verifies assertions with EngineBlock's signing
  certificate, mounted read-only. The mock makes no outgoing calls and imports no dev CA.
  This trust setup allows `sram.verify_peer: true`.
- **Trust on the host:** `bin/check.sh` passes `--cacert certs/openconext-dev-ca.crt`. Browsers need
  that CA imported by hand.
- **TLS 1.3 to DEZI:** DEZI requires TLS 1.3 (§10). HAProxy allows TLS 1.2 or later, so the mock does
  not enforce it on the server side. JIP's provider HTTP client must set
  `crypto_method: STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT` and `max_redirects: 0`. `libcheck --live`
  showed TLS 1.3 against DEZI acceptance.
- **EngineBlock → JIP:** `sram.base_url` points to JIP,
  `feature_enable_sram_interrupt` is on, `sram.verify_peer` is on, and `http_client.timeout` is 10
  (JIP's `engineblock.call_timeout_seconds` must equal it). The API token comes from
  `JIP_SBS_API_TOKEN` in `.env` (64 hex characters; JIP gets the same value as
  `EB_API_TOKEN`, the variable name in design §17). The DEZI attribute names are the placeholders
  from §6/§12.
- **Database port:** the overlay publishes MariaDB on `127.0.0.1:13306` by default. Set
  `DEVCONF_MARIADB_HOST_PORT` to use a different host port.

## Prerequisites

- Docker Engine with Compose ≥ 2.24 (`!override` support), a free
  Docker address pool for `core_coreconextdev`.
- The container images pinned in `env.dist`; download them with `bin/compose.sh pull`.
- Host names resolving to the Docker host and the development CA trusted by the browser; see below.
- The `acl` package (`setfacl` and `getfacl`) for bind-mount permissions.
- PHP 8.5 with `openssl` and `gmp`, and Composer 2 for dependency installation and host-side commands. Composer checks each
  application's required extensions.
- Installed dependencies for `../jip`, `../mock-dezi` and `../test-sp`; mock keys and ACLs prepared
  by `bin/setup.sh`.
- Python 3 with `requests` and `beautifulsoup4` for `bin/login-flow.py`.

## Commands

One-time preparation (no containers):

```bash
devenv/bin/setup.sh
sudo tee -a /etc/hosts <<'EOF'
127.0.0.1 engine.dev.openconext.local engine-api.dev.openconext.local manage.dev.openconext.local mujina-idp.dev.openconext.local profile.dev.openconext.local jip.dev.openconext.local mock-dezi.dev.openconext.local jip-test-sp.dev.openconext.local
::1 engine.dev.openconext.local engine-api.dev.openconext.local manage.dev.openconext.local mujina-idp.dev.openconext.local profile.dev.openconext.local jip.dev.openconext.local mock-dezi.dev.openconext.local jip-test-sp.dev.openconext.local
EOF
devenv/bin/check.sh
```

To trust the development CA in the Ubuntu system store, run from the repository root:

```bash
sudo install -m 644 devenv/certs/openconext-dev-ca.crt /usr/local/share/ca-certificates/dezi-openconext-dev-ca.crt
sudo update-ca-certificates
```

Restart your browser after installing the CA. If it uses a separate certificate store, import
`devenv/certs/openconext-dev-ca.crt` there as a trusted certificate authority. Add the host entries
on the machine running the browser; if it is a different machine, use the Docker host's address
instead of loopback and omit the `::1` entry.

First start (creates containers). EngineBlock needs its database before it turns healthy, as in
devconf's README:

```bash
devenv/bin/compose.sh pull
devenv/bin/compose.sh up                                   # terminal 1, stays attached
(cd devenv/upstream/OpenConext-devconf/core && ./scripts/init.sh)   # terminal 2: DB migrations, Manage entities, push
devenv/bin/compose.sh exec engine bash -c 'cd theme && yarn install --frozen-lockfile && yarn build'
devenv/bin/check.sh
```

`init.sh` runs `docker compose` in devconf's `core/` directory. `bin/compose.sh` uses the same
project name (`core`), so both reach the same containers.

Later starts, stop, and the POC services:

```bash
devenv/bin/compose.sh up -d --wait
devenv/bin/compose.sh down                                 # keeps the database volumes
# to start JIP, the mock DEZI provider and the test SP with the core: set COMPOSE_PROFILES=jip in devenv/.env
```

To change the pins, edit `.env` and re-run `bin/setup.sh`. It refuses to switch a checkout that has
local changes. The certificate is valid for 398 days. To renew it, delete
`upstream/OpenConext-devconf/core/haproxy/haproxy.{crt,pem}` and re-run setup.

**Authentication logs.** JIP and the mock provider use explicit Apache virtual hosts whose access
logs omit queries and headers, including `Referer`. Their error-log format omits Apache's default
`Referer` suffix as well. The virtual hosts prevent inheritance of the base image's full-request log. `setup.sh` replaces HAProxy's default HTTP request log with connection and response
metadata only. Rendering refuses unsupported logging directives or formats and keeps the previous
configuration on validation failure; `check.sh` applies the same guard to the generated file.
After changing these files in an existing stack, regenerate the proxy configuration
and reload HAProxy and both Apache servers before running a login. Verify only new log entries:
historical Docker logs can still contain credentials from earlier flows. Deployment-wide log
verification remains an acceptance requirement; see `jip/README.md`.

**Secrets in Compose.** `bin/compose.sh config` without `--quiet` prints the resolved configuration,
including `JIP_SBS_API_TOKEN`. Validate with `bin/compose.sh --profile jip config --quiet`, as
`bin/check.sh` does. To rotate the token, replace `JIP_SBS_API_TOKEN` in `.env` (for example with
`openssl rand -hex 32`) and recreate `engine` and `jip` together: both read it from `.env`, EngineBlock
as `sram.api_token` and JIP as `EB_API_TOKEN`.

**JIP container access.** The container's web-server user is `www-data` (uid 33,
`JIP_CONTAINER_WEB_UID`). `bin/setup.sh` gives it ACL search access on `jip/keys` and `jip/keys/mock`
(both mode 700), read access on the key files (mode 600), and read-write access on `jip/var`, with
default ACLs for new entries. No private key and nothing under `jip/var` is world-accessible. Re-run setup after creating new keys.

## Local integration (design §6–§8, §17)

The POC uses the **direct route**: the test SP is SBS-enabled itself and is not a trusted proxy (§8).
No trusted-proxy route is configured.

| Party | Setting | Where |
| --- | --- | --- |
| EngineBlock | `feature_enable_sram_interrupt: true`; `sram.base_url` = JIP; locations `authz`, `interrupt`, `attributes`; `sram.verify_peer: true`; `sram.api_token` from `JIP_SBS_API_TOKEN`; `sram.allowed_attributes` = the four reserved names (number, subscriber, role, login flag); `http_client.timeout: 10` | `engine/zz_jip_sbs.yaml` |
| Manage | The test SP with `coin:collab_enabled: true`, an explicit release policy of four organisation attributes (no reserved name, not the binding attribute, source `idp` only, no `release_as`), and one organisation connection `http://mock-idp` | `manage/jip-test-sp.json`, `php devenv/bin/manage.php apply` |
| JIP | Service `https://jip-test-sp.dev.openconext.local/saml/metadata`: allowed organisation `http://mock-idp`, policy version `mock-1`, release `dezi_nummer`, `abonnee_nummer`, `rol_code`, restart URL `https://jip-test-sp.dev.openconext.local/` | `../jip/config/jip/mock.yaml` |
| Test SP | §7 decision on the login flag and the reserved names; synthetic rules: subscriber `90000001`, role required, permitted role `01.000` | `../test-sp/config/test-sp.php` |
| Mujina | Synthetic accounts; the binding value is sent as a string attribute | `mujina/accounts.json` |

**Stepup.** All four triggers are empty (§9 item 10, §17 check 7): no `coin:stepup:requireloa` on
the service, no Stepup setting of `http://mock-idp` for it, no policy in Manage, and the test SP's
AuthnRequest carries no `RequestedAuthnContext`.

**Namespace and binding protection** (§4, §6, §17 checks 1–6, 17). The release policy lists no name
under `urn:mace:govroam.nl:attribute-def:dezi:` and not the binding attribute. There is no SP, IdP or
requester-SP attribute manipulation, no aggregation source and no `release_as` rule.
`feature_run_all_manipulations_prior_to_consent` is `false` (EngineBlock's default). The setting
is recorded, but only tested in its default state.

Apply and audit:

```bash
php devenv/bin/manage.php apply      # creates or updates the test SP in Manage and pushes to EngineBlock
php devenv/bin/manage.php audit      # read-only §17 checklist; exit 1 on any FAIL
python3 devenv/bin/login-flow.py accounts
```

`apply` exits unsuccessfully for push errors, including EngineBlock failures, transport failures and
unrecognized responses. The only tolerated error is the known unavailable devconf OIDC backend;
EngineBlock's service connections are still checked afterward. Run the push regression tests with
`jip/vendor/bin/phpunit --no-configuration devenv/tests/ManagePushTest.php`.

`audit` reads Manage, the running EngineBlock's parameters, JIP's mock configuration and the test SP's
rules. It does not prove the namespace protection with forged mixed-type values through EngineBlock
(§18): Mujina's form sends string values only, so `["untrusted-value", 1]` cannot be produced
here.

**Accounts** (Mujina, password `secret`):

| Account | Binding input | Expected |
| --- | --- | --- |
| `jip-anna` | `900000001` | with mock person `anna`: verified, test SP grants DEZI access; with `frank`: `binding_mismatch` |
| `jip-bram` | `900000002` | verified after profile selection; refused by the SP's subscriber or role rule |
| `jip-carla` | `900000003` | verified without role; refused by the SP, which requires a role |
| `jip-dirk` | `900000004` | verified with role `00.000`, released unchanged; refused by the SP's role list |
| `jip-eva` | `900000005` | `statement_not_active` (revoked) |
| `jip-nonumber`, `jip-empty`, `jip-spaces` | absent, `""`, `"   "` | skipped, organisation-level access. EngineBlock trims the spaces before the start call |
| `jip-multi` | two values | `malformed_binding` |
| `jip-forged` | valid, plus a `…dezi:login` value | `reserved_attribute` |

Mujina cannot send an `xs:integer` value, so the integer case is not covered here.

**Running a login:**

```bash
python3 devenv/bin/login-flow.py login jip-anna --person anna --expect dezi --show-attributes
python3 devenv/bin/login-flow.py login jip-nonumber --expect organisation
python3 devenv/bin/login-flow.py login jip-bram --person bram --profile bram-ggd-zuid --expect refused
python3 devenv/bin/login-flow.py login jip-anna --person anna --dezi-action cancel --expect jip-error:provider_cancelled
```

Run the test SP's automated checks with `composer --working-dir=test-sp check`. Its tests cover
SAML response handling, session renewal and logout, configuration, and the §7 access decisions.

The script prints only the scheme, host and path of each step. It ends with the test SP's decision
(`dezi`, `organisation` or `refused`) or JIP's error page: the failure type, log ID and whether a
restart link is shown. A browser works too: open https://jip-test-sp.dev.openconext.local/ and log in
at Mujina as one of the accounts above.

**Correlation** (§20). Each JIP log line names the separate log ID. The start, delivery and failure
lines also name the service, the organisation, the policy version at start (and at delivery), and
EngineBlock's request ID. That ID is the `ID` of the return URL, which equals the test SP's
AuthnRequest ID (`ONELOGIN_…`). The test SP shows the same ID on its result page and logs it, so a
login can be traced from SP to JIP.

**Logging boundaries.** JIP, the mock DEZI provider, the test SP and HAProxy are configured to
omit credentials and sensitive payloads. Verify their logs after changing logging configuration.

- **EngineBlock** uses devconf's stock Apache log format, which includes the SP's `SAMLRequest`
  and `RelayState` query on `/single-sign-on`, and the return URL with `?ID=`. EngineBlock's own
  logging is outside JIP; on govConext it is an operator's §20 obligation (§10, Prolocation row).
- **Mujina, Manage and Profile** require separate log verification.
- Verify tracing redaction in any deployment that enables tracing.
- Docker can retain logs from before a configuration change. Check only new entries.

## Library choice (design §19)

**JOSE: `web-token/jwt-library` 4.2.x** (4.2.3 verified; requires PHP ≥ 8.2; with
`spomky-labs/pki-framework` 1.6.3 and `brick/math` 1.0.0).
`web-token/jwt-bundle` 4.2.3 (Symfony ^7|^8) is optional and not needed.

**OIDC: no third-party OIDC client.** A thin client in JIP's OIDC part (§2) on
`symfony/http-client` 7.4 and web-token. The design takes trust from configuration, never from
discovery or the token: an approved key address per message type, the ID-token issuer from
`provider.expected_issuers.id_token` (which may differ from the discovery issuer), the
authentication method from configuration, no redirects, and TLS 1.3. Generic clients derive this
from discovery.

| Candidate | Finding | Basis |
| --- | --- | --- |
| `facile-it/php-openid-client` 1.0.0 (web-token ^4) | private_key_jwt header has only `alg` and `jti` (no `kid`, no `x5t#S256`) and uses `time()`. The ID-token `iss` is the discovery issuer. `auth_time` is checked against `max_age`, not the attempt start. JWKS come from the issuer provider. It brings PSR-7/18, `php-http/discovery` (a Composer plugin) and middleware. DEZI's nested UserInfo would bypass it anyway. | source review |
| `league/oauth2-client` 2.9.1 | code flow and PKCE, but no ID-token validation and no `private_key_jwt`. PHP constraint `<8.6`. Brings Guzzle. | Packagist metadata |
| `jumbojett/openid-connect-php` 1.0.2 | phpseclib-based. Trusts keys and methods from discovery. No DEZI-style JWE handling. Last release 2024. | Packagist metadata |
| `drenso/symfony-oidc-bundle` 4.5.0 | a security firewall authenticator on `lcobucci/jwt`, which has no JWE. It would need a second JOSE library. | Packagist metadata |

**Library checks:** `php devenv/libcheck/verify.php [--live]`. A Symfony `MockHttpClient` plays the provider, so every request is really built
and parsed:

- authorization code flow: the authorisation request with `code`, `state`, `nonce`, PKCE `S256`
  (RFC 7636 test vector), `prompt=login` and `max_age=0`; the token exchange; the UserInfo call with
  the bearer token;
- `private_key_jwt` with RS256: header `alg`, `kid` and `x5t#S256`; claims `iss`=`sub`=client ID,
  `aud`=token endpoint, a lifetime of 60 s and a fresh `jti`. A repeated `jti`, a wrong `aud`, a
  wrong key, an expired assertion and a wrong PKCE verifier are refused;
- JWS verification limited to RS256 and the supplied key set. It refuses `none`, HS256 key
  confusion, an unapproved key with the same `kid`, a `jku` pointing elsewhere (never followed), a
  tampered payload, and a wrong `iss`, `nonce`, `aud` or `auth_time`;
- JWE `RSA-OAEP` + `A256CBC-HS512`, followed by verification of the nested JWS against a separate key
  set. It refuses `RSA-OAEP-256` and `A128GCM`. A response for the previous key decrypts while both
  keys are configured and fails after that key is removed;
- `--live`: DEZI acceptance discovery returns 200 over TLS 1.3 with redirects disabled. It lists
  `none` and `private_key_jwt` and `S256`.

**Validation JIP must implement itself** (the libraries do not do it):

- Discovery: exact `issuer` match; `jwks_uri` equal to `provider.approved_key_addresses.id_token`;
  the configured authentication method listed in `token_endpoint_auth_methods_supported`; HTTP with
  `max_redirects: 0`, TLS 1.3 and timeouts.
- Keys: one key set per message type, from its own approved address; a cache per address; a `kid`
  looked up only in that set; one rate-limited refetch for an unknown `kid`; a supplied `jku` exactly
  equal to the approved address. web-token never follows `jku`, so the check is explicit.
- Client assertion: the `x5t#S256` header is computed by JIP, because web-token's
  certificate import names the thumbprint `x5t#256`. A new `jti` for every request; the assertion is
  never stored or logged.
- State, cookie, nonce, PKCE verifier and attempt start: generated, stored and compared with
  `hash_equals`. The callback's `error` parameter is handled.
- Token response: HTTP 200, `token_type` `Bearer`, `id_token` and `access_token` present;
  `invalid_client` has its own failure type.
- ID token: the mandatory claims list; `nonce` equality; `aud` contains the client ID and no other
  value (`AudienceChecker` alone accepts extra audiences); the `azp` rule; `auth_time` between the
  attempt start and now within the skew (not `max_age`); `iss` from configuration.
- JWE: an explicit `alg`/`enc` allowlist with a named failure; decryption keys tried with the
  matching `kid` first, then newest first (web-token tries the set in order and ignores `kid`).
- Envelope and statement (DEZI profile, §14 and §16): issuer, audience and assurance values as the
  CIBG confirms them, `sub` binding, `verklaring_id` (UUID, equal in both), claim types and the null
  rule, string identifiers.
- Revocation list: the digit-string `nbf`, `exp` and `ververs_tijdstip` must be converted before the
  library's time checkers, which reject strings (verified).
- Core: the account binding, the reserved namespace and the transaction rules (§4, §6, §13) do not
  involve these libraries.

## Mock assumptions and confirmed requirements

| Item | Status |
| --- | --- |
| EngineBlock 7.2.1 for govConext | Confirmed (§10) |
| Manage ≥ 9.1.0 on govConext | **Open** (§10) |
| DEZI: code flow, PKCE S256, RS256 ID token, JWE `RSA-OAEP`/`A256CBC-HS512`, TLS 1.3 | From the v0.7 specification and acceptance discovery (§14) |
| DEZI accepts `private_key_jwt` for a registered client, and the assertion contents | **Open** (§10). The libraries support both `private_key_jwt` and `none`; configuration decides |
| `mock-dezi.dev.openconext.local` as one host for all DEZI endpoints and key addresses | Mock only. Key addresses stay per message type in the configuration |
| Attribute names `urn:mace:govroam.nl:attribute-def:dezi:*` and the binding attribute | Placeholders until govroam agrees them (§10) |
| Keys and claims in `libcheck/verify.php` | Test data for the libraries only; not DEZI's message format |
| Message shapes, fixtures and behaviour of the mock DEZI provider | **Provisional** mock choices, listed in [mock-dezi/README.md](../mock-dezi/README.md) ("PROVISIONAL assumptions") |
