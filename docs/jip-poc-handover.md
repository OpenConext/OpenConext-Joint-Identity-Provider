# JointIdentityProvider (JIP) proof of concept: handover

**Status:** proof of concept. Not an acceptance deployment and not production-ready.

**Design source:** [2026-10-05-high-level-design-dezi-connector.md](2026-10-05-high-level-design-dezi-connector.md).
JIP is the service the design calls the "DEZI connector". DEZI is the external identity provider
run by the CIBG; its claims, attribute names, endpoints and the mock DEZI provider keep the DEZI
name. EngineBlock's `sram.*` settings and the SBS contract are unchanged.

## 1. What the proof of concept is

The POC follows design §11: OpenConext-devconf with EngineBlock 7.2.1, the mock DEZI provider built
from DEZI's specification v0.7, and automated tests. It contains:

| Part | Where | Notes |
| --- | --- | --- |
| JIP: core, OIDC client, DEZI profile | [jip/](../jip/README.md) | Namespace `JointIdentityProvider\{Core, Oidc, Profile\Dezi}`; single-node SQLite store, mock environment only |
| Mock DEZI provider | [mock-dezi/](../mock-dezi/README.md) | Synthetic people and statements; selectable failures; every value is a **provisional** mock choice |
| Test SP | `test-sp/` | Makes the design §7 access decision with synthetic rules |
| Local environment | [devenv/](../devenv/README.md) | devconf core, EngineBlock override, Manage entity, Mujina accounts, scripts |

Outside the POC, as design §11 states: the shared store, the optional revocation list, monitoring,
deployment artefacts, key rotation in operation, a trusted-proxy route and the real GGD applications.
The direct SBS route is the only route configured.

**DEZI acceptance is not verified.** A test against DEZI acceptance needs the CIBG client
registration, confirmed values for every `<…>` placeholder in
[jip/config/jip/acceptance.yaml.dist](../jip/config/jip/acceptance.yaml.dist), and a transaction store
that JIP accepts outside the mock environment (§5 of this document).

## 2. Setup (once per machine)

Prerequisites, versions and background are in [devenv/README.md](../devenv/README.md). In short, from
the repository root:

1. Install Docker Engine with Compose ≥ 2.24, PHP 8.5 with `openssl` and `gmp`, Composer 2, and
   Python 3 with `requests` and `beautifulsoup4`, plus the `acl` package (`setfacl`/`getfacl`).
2. Install dependencies: `composer --working-dir=jip install`, `composer --working-dir=mock-dezi install`,
   `composer --working-dir=test-sp install`.
3. Prepare the environment: `devenv/bin/setup.sh`. It fetches devconf and
   EngineBlock 7.2.1, writes `devenv/.env` with a new `JIP_SBS_API_TOKEN`, creates the development CA,
   the HAProxy configuration, the EngineBlock SBS drop-in, JIP's mock client keys, the mock DEZI
   provider's keys and the container ACLs.
4. Add the host names to `/etc/hosts` and trust `devenv/certs/openconext-dev-ca.crt` in the browser
   ([Commands](../devenv/README.md#commands)).
5. Set `COMPOSE_PROFILES=jip` in `devenv/.env` to start JIP, the mock DEZI provider and the test SP
   with the core.
6. Check: `devenv/bin/check.sh` (exit 0 means no `FAIL`; read every `MISSING`).

## 3. Initialization (once per new stack)

```bash
devenv/bin/compose.sh pull
devenv/bin/compose.sh up                                              # terminal 1
(cd devenv/upstream/OpenConext-devconf/core && ./scripts/init.sh)     # terminal 2: databases, Manage, push
devenv/bin/compose.sh exec engine bash -c 'cd theme && yarn install --frozen-lockfile && yarn build'
php devenv/bin/manage.php apply          # the test SP in Manage, pushed to EngineBlock
python3 devenv/bin/login-flow.py accounts   # the synthetic Mujina accounts
devenv/bin/check.sh
php devenv/bin/manage.php audit          # design §17 operator checklist, read-only; exit 1 on any FAIL
```

JIP's container starts Apache only when `jip:config:validate` passes as the web-server user.

## 4. Startup and shutdown

| Action | Command |
| --- | --- |
| Start or resume everything | `devenv/bin/compose.sh up -d --wait` |
| Start only the POC services | `devenv/bin/compose.sh up -d --wait jip mock-dezi jip-test-sp` |
| State | `devenv/bin/compose.sh ps`, `curl --cacert devenv/certs/openconext-dev-ca.crt https://jip.dev.openconext.local/health` |
| Stop, keeping databases | `devenv/bin/compose.sh --profile jip stop` |
| Remove containers, keeping database volumes | `devenv/bin/compose.sh down` |
| Check JIP's configuration in the container | `docker exec -u www-data -w /var/www/html core-jip-1 php bin/console jip:config:validate` |

After a restart, run `python3 devenv/bin/login-flow.py accounts` again if Mujina no longer knows the
accounts.

## 5. Fixture and state reset

| What | Reset |
| --- | --- |
| Mock DEZI provider (logins, codes, tokens, used assertion IDs, scenario, endpoint modes, statement behaviours) | `curl -X POST -H 'Content-Type: application/json' --cacert devenv/certs/openconext-dev-ca.crt https://mock-dezi.dev.openconext.local/mock/reset`, or restart the `mock-dezi` container |
| JIP's provider cache (DEZI discovery metadata, key sets, fetch back-off) | `docker exec -u www-data -w /var/www/html core-jip-1 sh -c 'rm -rf "var/cache/$APP_ENV/jip-provider"'` |
| JIP's transactions | `docker exec -u www-data -w /var/www/html core-jip-1 rm -f var/jip/transactions.sqlite`; JIP recreates the store. Open logins are lost. Expired records are also pruned on every write |
| Mujina accounts | `python3 devenv/bin/login-flow.py accounts` |
| Test SP in Manage and EngineBlock | `php devenv/bin/manage.php apply`, then `php devenv/bin/manage.php audit` |
| EngineBlock SBS settings | `devenv/bin/setup.sh`, or `install -m 644 devenv/engine/zz_jip_sbs.yaml devenv/upstream/OpenConext-engineblock-7.2.1/config/packages/dev/`. Then `touch` that file: EngineBlock's development cache compares modification times in whole seconds, so a change in the same second as a cache rebuild stays unseen |
| Mock DEZI keys | Delete `mock-dezi/keys/`, run `mock-dezi/bin/init-keys` and `devenv/bin/setup.sh`, then clear JIP's provider cache |
| JIP's mock client keys | Delete `jip/keys/mock/`, run `jip/bin/init-mock-keys` and `devenv/bin/setup.sh`; the mock reads the new certificates on the next request |
| Synthetic people and profiles | [mock-dezi/fixtures/profiles.yaml](../mock-dezi/fixtures/profiles.yaml) and [devenv/mujina/accounts.json](../devenv/mujina/accounts.json) |

`manage.php audit` reads EngineBlock's parameters through the console. After an EngineBlock
configuration change, confirm the web process with a login as well.

## 6. Demonstration

Open https://jip-test-sp.dev.openconext.local/ in a browser that trusts the development CA, choose
**Log in**, sign in at Mujina as one of the accounts below (password `secret`), and pick a person
and, where offered, a profile on the mock DEZI provider's page. The scripted equivalent prints each
host on the route and the test SP's decision or JIP's error page.

| # | Shows (design) | Command |
| --- | --- | --- |
| 1 | Verified login, binding, released DEZI attributes, login flag `verified` (§3, §4, §6) | `python3 devenv/bin/login-flow.py login jip-anna --person anna --expect dezi --show-attributes` |
| 2 | Skip without a DEZI page, flag `skipped`, organisation-level access (§3, §4) | `python3 devenv/bin/login-flow.py login jip-nonumber --expect organisation --show-attributes` |
| 3 | EngineBlock trims a whitespace value to empty: skip (§4) | `python3 devenv/bin/login-flow.py login jip-spaces --expect organisation` |
| 4 | Profile selection; the selected profile's subscriber and role (§3, §6) | `python3 devenv/bin/login-flow.py login jip-bram --person bram --profile bram-ggd-zuid --show-attributes` |
| 5 | No role released for a profile without one; `00.000` released unchanged; the test SP decides (§6, §7) | `… login jip-carla --person carla --show-attributes`, `… login jip-dirk --person dirk --show-attributes` |
| 6 | Another person's DEZI login: final `binding_mismatch` (§4) | `… login jip-anna --person frank --expect jip-error:binding_mismatch --restart no` |
| 7 | Malformed binding and a forged reserved name stop at the start call (§4, §6) | `… login jip-multi --expect jip-error:malformed_binding`, `… login jip-forged --expect jip-error:reserved_attribute` |
| 8 | Cancel at DEZI: restartable, with a restart link (§13) | `… login jip-anna --person anna --dezi-action cancel --expect jip-error:provider_cancelled --restart yes` |
| 9 | Revoked statement, and an unanswered status check (§15) | `… login jip-eva --person eva --expect jip-error:statement_not_active`, `… login jip-anna --person anna --scenario status_timeout --expect jip-error:status_check_unavailable --restart yes` |
| 10 | Result delivered once, concurrent calls, two tabs, replay (§13) | `python3 devenv/bin/sbs-flow.py run premature-repeat concurrent two-tabs callback-replay` |
| 11 | Organisation refusal and withdrawal before delivery (§8, §13) | `python3 devenv/bin/sbs-flow.py run organisation withdrawal` |
| 12 | Renewal at delivery, revocation after login, the 10 s EngineBlock budget (§13, §15) | `python3 devenv/bin/sbs-flow.py run renewal` |
| 13 | Correlation without credentials (§20) | After demo 1: `docker logs --since 5m core-jip-1 2>&1 \| grep 'JIP '` and `docker logs --since 5m core-jip-test-sp-1 2>&1 \| grep ONELOGIN_` |

`…` stands for `python3 devenv/bin/login-flow.py login`. Every mock DEZI scenario is listed with
`curl --cacert devenv/certs/openconext-dev-ca.crt https://mock-dezi.dev.openconext.local/mock/scenarios`
and selected with `--scenario <name>`. `withdrawal` edits `jip/config/jip/mock.yaml` for a few seconds
and restores it byte for byte.

**Operator-configuration demonstrations** (§6, §8, §17; change Manage or EngineBlock, so restore
afterwards with §5):

- Mixed-type forgery: in Manage, give the IdP `http://mock-idp` the attribute manipulation
  `$attributes['urn:mace:govroam.nl:attribute-def:dezi:abonnee-nummer'] = array('untrusted-value', 1);`
  and push. Demo 1 still shows only subscriber `90000001`: EngineBlock leaves the attribute out of the
  start call and the release policy removes it. `manage.php audit` reports `FAIL`. With
  `array('untrusted-value')` the login stops with `reserved_attribute`.
- Binding changed after the organisation: `$attributes['urn:mace:govroam.nl:attribute-def:organisation-dezi-nummer'] = array(900000001);`
  or `unset(...)` turns demo 1 into a skip; `array('   ')` gives `malformed_binding`. This is why
  operator check 17 forbids such rules.
- Integration off: set `coin:collab_enabled` to false on the test SP and push. EngineBlock no longer
  calls JIP, the assertion has no login flag and the test SP grants organisation-level access only.
- Missing allowed attribute: remove the role code or the login flag from
  `sram.allowed_attributes` in the installed EngineBlock drop-in. The test SP then refuses DEZI-based
  access.

## 7. Repeatable verification

```bash
APP_ENV=test composer --working-dir=jip check     # lint, phpcs, phpstan max, phpunit
composer --working-dir=mock-dezi check
composer --working-dir=test-sp check
jip/vendor/bin/phpunit --no-configuration devenv/tests/ManagePushTest.php
bash devenv/tests/haproxy-logging.sh
devenv/bin/check.sh
php devenv/bin/manage.php audit
devenv/bin/verify-poc.sh                          # running stack; --quick skips sbs-flow.py's withdrawal and renewal cases
```

`verify-poc.sh` runs every browser login and mock DEZI scenario with its expected outcome and restart
link, the discovery failure modes, an unanswered key refetch, and every `sbs-flow.py` case. It resets
the mock DEZI provider and clears JIP's provider cache. It changes nothing in Manage or EngineBlock.

## 8. Implementation limitations

DEZI acceptance requires CIBG client registration, confirmed values in
`acceptance.yaml.dist`, and a transaction store accepted outside `environment: mock`.
A shared store or an explicit decision on a single-node acceptance test is needed first.
Real application acceptance contracts, session limits and revocation delays require agreement
with the application owners (design §7, §10).

The trusted-proxy route, revocation list and multi-node rollout are outside the POC configuration.

### Restart behaviour deviations from design §§13 and 18

The proof of concept uses the restartable failure list in `jip/README.md`. In addition to the
requests listed in the design, `discovery_unavailable` and `userinfo_unavailable` are restartable:
a fresh login can recover from an unanswered metadata or UserInfo request. The core also treats
`already_used` as restartable when its service is known.

An unknown nonce or callback `state` has no known transaction, service, log ID or approved restart
URL. Its page therefore asks the user to start again from the application and offers no restart
link. A state/cookie mismatch for a known transaction remains restartable. This is an explicit
exception to the design's general restart-link rule for unknown links. `verify-poc.sh` expects
`callback_wrong_state` to produce `link_not_valid` with no restart link.

## 9. Outstanding CIBG questions (design §10)

None is answered. Each blocks a placeholder in `acceptance.yaml.dist` or a mock assumption; none may
be filled from the mock.

1. Does DEZI acceptance and production accept, require or refuse `private_key_jwt` for a registered
   client, and how is the signing key registered (second certificate, key-set address, or the single
   encryption certificate)? Do the environments differ?
2. What must the client assertion contain: algorithm, `aud` (token endpoint or issuer), maximum
   lifetime, key-selecting header (`kid`, `x5t#S256`), `jti` replay handling, tolerated clock skew?
3. Which specification version is final, and does acceptance follow it?
4. Example messages for every step: how UserInfo is tied to the ID token's subject (envelope `sub`
   or an approved access-token association), the key address that signs each message type
   (the envelope key is described in two ways), the issuer and audience of each message type
   including the ID token's `iss` on acceptance, the envelope audience for this client, the envelope
   claim that carries the statement, and where `jku` appears.
5. Login freshness: is `max_age` supported, is `auth_time` always returned, how old may a login be,
   and how much clock difference is tolerated?
6. Is the per-statement status check sufficient on its own; which status values exist besides
   `actief`; what does a removed statement answer; which field names apply (`verklaringId` or
   `verklaring_id`, `status`)? If the revocation list is also required: what `ververs_tijdstip` means
   and how long a list may be used after it.
7. Exact formats: the high-assurance value per claim (`loa_authn`, `loa_dezi`), timestamps, role codes,
   how a profile without a role is represented, and which optional claims may be `null`.
8. Which error codes DEZI returns at the callback for a cancel and for an error (the mock uses
   RFC 6749 `access_denied` and `server_error`).
9. May one client registration serve several applications and care organisations?
10. Certificate replacement for the decryption and signing certificates: lead time, overlap of two
    certificates, and whether DEZI checks the certificate's validity period.
11. With GGD GHOR: may JIP pass DEZI's signed statement on to applications?

## 10. Other open dependencies (design §10)

- **Prolocation:** Manage ≥ 9.1.0 on govConext; the
  real service, IdP-manipulation and aggregation settings; the shared store with atomic
  compare-and-set; clocks, timeouts, `http_client.timeout` and TLS 1.3; log redaction including
  EngineBlock's own log and both token headers; tested correlation.
- **govroam, application owners:** the versioned organisation list and its change process; the
  attribute names and namespace (the names here are placeholders); the repository name; per
  application the required attributes, roles, subscribers, restart URL, rules for logins without
  DEZI, session limits and revocation delay; confirmation that no application requests a Stepup
  level in its login request; a real-application test that missing DEZI attributes or a login flag
  other than `verified` grant no DEZI-based access; the compliance and audit review.
- **GGD GHOR:** the provisioning contract for the DEZI number, and IdPs that send it as a string.
- **SURF:** the organisation's level in the assertion; a possible EngineBlock merge change; the Stepup
  nonce fix if an application needs Stepup.
