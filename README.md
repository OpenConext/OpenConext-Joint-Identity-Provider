# JointIdentityProvider (JIP)

JIP is the service the design calls the "DEZI connector"
(`docs/2026-10-05-high-level-design-dezi-connector.md` in jip-dev).
It implements EngineBlock's SBS interface on one side and is an OpenID Connect client of DEZI on the
other. "DEZI" names only the external provider, its profile, its claims and attribute names, and the
mock that imitates it.

This is the proof of concept. It contains the Symfony application, the configuration contract with
its startup checks (§17), `GET /health`, the shared MariaDB transaction store, EngineBlock's start call
`POST /authz` with the skip decision, the browser hand-off, the standard OIDC code flow, the DEZI
profile (UserInfo decryption, envelope, statement and revocation checks), the account binding, the
claim mapping and EngineBlock's result call `POST /attributes` (§4, §12–§17). A verified result or
a skip is delivered to EngineBlock once; failed, revoked, expired, withdrawn and consumed
transactions release no attributes. The EngineBlock integration, Mujina accounts, test SP and
JIP-branded error pages are described in
Local integration (`devenv/README.md`, section "Local integration", in jip-dev).

The development environment, mock DEZI provider, test SP and POC documentation live in the
separate jip-dev repository, which checks this repository out as `jip/`.
Paths starting with `devenv/` or `docs/` in this README refer to that repository.

## Structure

| Part | Namespace | Holds | DEZI-specific |
| --- | --- | --- | --- |
| Core | `JointIdentityProvider\Core` | configuration contract and startup checks, claim mapping, account binding, service policies, transaction store, profile interfaces, result delivery, `/health`, `jip:config:validate` | No. Claim and attribute names come from the configuration or from the profile |
| OIDC client | `JointIdentityProvider\Oidc` | discovery, authorisation with PKCE, token exchange (`none`, or optional `private_key_jwt` client assertions), signing-key cache, ID-token and signed-message validation | No |
| Shared configuration readers | `JointIdentityProvider\Configuration` | `ConfigNode` and `ConfigurationErrors`, used by every part to read and report on the configuration tree | No |
| DEZI profile | `JointIdentityProvider\Profile\Dezi` | `provider.profile: dezi`: UserInfo decryption, envelope and statement checks, the status check and its renewal, its message types (`envelope`, `statement`), releasable claims, binding claim `dezi_nummer`, `expected_assurance`, `envelope`, `statement`, `revocation` | Yes |

Dependency direction, enforced by deptrac (see "Quality checks"): the shared configuration readers
depend on no other part, Oidc only on them, Core also on Oidc, and profiles on all three.

Interfaces between the parts:

- `Core\Transaction\TransactionStore`: add, find, find by OIDC `state`, and one atomic compare-and-set
  per state change that also requires the deadline to lie ahead (§13). An optional `$validUntil`
  must also lie ahead of the time sampled at write; result delivery passes the recheck's validity.
  Implementations must check `Transaction::assertCanBeReplacedBy()` inside the atomic operation:
  start fields stay fixed and an assigned result deadline can only be shortened.
- `Core\Profile\ProfileResult`: the verified claim set (claim name to string values), the hard
  expiry, and profile-owned recheck data.
- `Core\Profile\ProviderProfile`: what the core asks a profile, including `validateLogin()` after
  the standard OIDC checks and `recheck()` at result delivery (at most one outgoing request).
  `RecheckResult::passed()` refuses a renewal that would extend the hard expiry. Profiles are found
  by the `jip.provider_profile` tag.

## Requirements

PHP 8.5 with `openssl`, `gmp` and `pdo_mysql` using mysqlnd, Composer 2, Symfony 7.4 and `web-token/jwt-library`
4.2 or later in the 4.x series. MariaDB 10.6 for the transaction store (jip-dev's `jip-mariadb`
service runs 10.6.24). Binary logging must be off, or `binlog_format` must be `ROW` or `MIXED`: the
store uses `READ COMMITTED`, which InnoDB cannot write under statement-only binary logging.

## Getting started (mock)

```bash
composer install
bin/init-mock-keys                                    # the test decryption key under keys/mock/ (git-ignored)
cp .env.local.dist .env.local                         # selects dev; fill in EB_API_TOKEN (>= 32 characters)
bin/console jip:config:validate                       # the startup checks; exit 1 on any problem
bin/console jip:store:init                            # create the table before serving requests
php -S 127.0.0.1:8000 -t public public/index.php      # then: curl http://127.0.0.1:8000/health
```

The committed default is `APP_ENV=prod`. The local override above explicitly selects `APP_ENV=dev`,
which loads `.env.dev` and selects `config/jip/mock.yaml` and `CONNECTOR_ENVIRONMENT=mock`.
In devconf the `jip` service gets the same values, with `EB_API_TOKEN` taken from `devenv/.env`
(`JIP_SBS_API_TOKEN`) and `JIP_DATABASE_PASSWORD` for the `jip-mariadb` service. `mock.yaml` names
that service's host, which resolves only inside the Compose network.

## Configuration

| Variable | Meaning |
| --- | --- |
| `JIP_CONFIG_FILE` | The configuration file. A relative path resolves against the project directory. Not set in `.env`, so a deployment never falls back to the mock |
| `CONNECTOR_ENVIRONMENT` | `mock`, `acceptance` or `production`. Must equal `environment` in the file (design §17). Not set in `.env` |
| `EB_API_TOKEN` | EngineBlock's `sram.api_token`, referenced from the file as `'%env(EB_API_TOKEN)%'` |
| `JIP_DATABASE_PASSWORD` | The store's database password, referenced from the committed files as `'%env(JIP_DATABASE_PASSWORD)%'` |

The file implements the design's §17 contract, including `provider.profile: dezi` and the attribute
identifiers, with the additional validation rules below. Each client also requires `redirect_uri`;
the §17 sample does not include it. `%env(NAME)%` is allowed only as a whole value.

| File | Purpose |
| --- | --- |
| `config/jip/mock.yaml` | The local mock DEZI. Values marked "mock assumption" are not confirmed DEZI values and stay in this file |
| `config/jip/acceptance.yaml.dist` | The §17 acceptance template. JIP refuses it until every `<…>` is replaced with an approved value |

**Startup checks.** `jip:config:validate` and `GET /health` use the same §17 checks. Unreadable or
invalid YAML is reported first; environment references and placeholders must be resolved before
schema validation runs. Schema validation collects independent problems together; checks that depend
on invalid values wait until those values are fixed. Diagnostics name configuration paths, never
configured values. The command prints them; `/health` logs them and returns only `DOWN` on failure.

**Intentional validation rules beyond §17.** These are deliberate and stay:

- unknown settings at any level are refused, so a misspelt key never silently falls back;
- client keys must be RSA of at least 2048 bits (`RS256` and `RSA-OAEP`, design §14);
- `provider.authorization.scope` must include `openid`;
- every `provider.clients.<id>.redirect_uri` is required and must be an absolute HTTPS URL with
  exactly the path `/oidc/callback`, with no query or fragment. Register that exact URL with the
  provider; the transaction cookie is sent only to this path;
- every claim under `attributes.claims` must be one the profile can deliver;
- no claim may map onto `attributes.login_flag` or onto another claim's attribute name;
- a service's `release` holds no duplicates;
- `engineblock.return_url_prefix` must include a path and have no query or fragment. Both the
  start call and the skipped hand-off validate the return URL's scheme, host, port and exact path
  against the configured prefix before accepting it or redirecting.

**Client authentication** (design §10, §14). `provider.clients.<id>.authentication` must be set
explicitly; there is no default.

- `none` is the DEZI method: the CIBG treats JIP as an open client. The token request carries
  `grant_type`, `code`, `redirect_uri`, `code_verifier` and `client_id`, and no client assertion. A
  `signing_key` is refused with `none`. `acceptance.yaml.dist` and `mock.yaml` use it.
- `private_key_jwt` is an explicit option, only if the CIBG asks for it. It requires `signing_key`
  (`certificate`, `private_key`, optional `kid`, `assertion_lifetime_seconds`) and adds
  `client_assertion_type` and a fresh `RS256` `client_assertion` to every token request. How DEZI
  registers the signing key and what the assertion must contain are open CIBG questions (§10).
- PKCE `S256` is sent with every authorisation request and cannot be switched off.
- `decryption_keys` are required with either method: DEZI encrypts UserInfo for the registered
  certificate.
- The configured method must appear in discovery's `token_endpoint_auth_methods_supported`; a
  missing list supports no method. Otherwise the login fails with
  `authentication_method_not_supported` before the token request. JIP never derives the method from
  discovery and never retries with another method; `invalid_client` fails with
  `client_authentication_refused`.

**DEZI profile settings beyond the §17 sample** (design §14, §16). The §17 sample has no place for
these DEZI contract points, so `provider` carries two profile-owned blocks:

- `provider.envelope.statement_claim`: the envelope claim that carries the sealed statement. It may
  not be one of the envelope's own claims (`iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `loa_authn`,
  `verklaring_id`).
- `provider.envelope.subject_association`: `envelope_sub` (the envelope must carry a `sub` equal to
  the ID token's) or `access_token` (specification v0.7: no envelope `sub`; only with a
  CIBG-approved contract). A supplied envelope `sub` must equal the ID token's in both modes;
  `dezi_nummer` never stands in for it.
- `provider.envelope.audiences.<client>`: the envelope `aud` confirmed for each client under
  `provider.clients`. It is not assumed to equal the client ID or the SAML service ID.
- `provider.statement.nullable_claims`: optional statement claims whose `null` the confirmed contract
  permits as absent. `dezi_nummer` and `abonnee_nummer` cannot be listed. Any other `null`, and the
  string `"null"`, fails validation.

**Proof-of-concept limitations.** The revocation list is not supported: JIP refuses
`revocation.mode: status_check_with_list`, `revocation.list_address`, and a `revocation_list` entry
under `approved_key_addresses` or `expected_issuers`. Only `status_check` is used (design §15).
`transactions.store` is a map of `host` (host name or IP address), `port`, `database` (letters,
digits and underscores, at most 64), `user`, `password` and `tls_ca`: a MariaDB 10.6 database shared
by every JIP node (§10, §13), in every environment. Use `127.0.0.1` for local TCP connections;
`localhost` is refused because PDO would use a Unix socket and ignore `port`. Keep the port in
`port`, not in `host`; colons are accepted only in a valid, unbracketed IPv6 address.
`tls_ca` is an absolute path to a readable CA certificate file. It is required in acceptance and
production, and optional in mock. When supplied, the connection verifies the server certificate
and refuses an unencrypted session. Omitting it in mock permits plaintext database traffic; use
this only on the isolated local development network.

Before serving requests, run `bin/console jip:store:init` with a deployment account that has
`CREATE` on the database. The command creates `jip_transactions` if absent and is safe to repeat;
it does not migrate an existing table. Then configure the runtime account with only `SELECT`,
`INSERT`, `UPDATE` and `DELETE`. Use a deployment configuration file or environment credentials
for initialization; do not leave the deployment account in the web application's configuration.
The local mock container runs this command after configuration validation using its development
account. Runtime connections never execute schema DDL. Every add or compare-and-set write prunes
expired records. Cleanup depends on writes; it does not guarantee a retention limit during idle periods.

## Transactions and `POST /authz`

- **Store.** `Core\Storage\MariaDbTransactionStore` reads a record with `SELECT … FOR UPDATE` and
  replaces it in the same InnoDB transaction, so the compare-and-set holds a row lock across
  processes and nodes. Connections use `READ COMMITTED`, strict SQL mode, server-side prepared
  statements and 2-second limits for connecting, network reads, InnoDB row-lock waits,
  metadata-lock waits and SQL statements. These limits apply per operation, not to a whole request;
  multiple operations can accumulate. The mysqlnd read timeout is set when opening the connection
  and the previous process setting is restored afterwards. Identifiers compare byte for byte
  (`utf8mb4_nopad_bin`).
  `add()` accepts only `pending`, `skipped` or `failed`; replacements follow the §13 state diagram
  (`TransactionState::canMoveTo()`), keep the start fields and never extend a deadline. Records past
  their deadline are removed when a transaction is added; every endpoint treats them as expired.
- **Authentication.** The raw `Authorization` header must equal `engineblock.api_token` exactly
  (no `Bearer`). `Authentication` is never read. Otherwise `401 {"msg":"error"}`.
- **Request.** `user_id`, `continue_url`, `service_id`, `issuer_id` (non-empty strings) and
  `attributes` (a map, `[]` allowed) are required; otherwise `400 {"msg":"error"}`. A missing
  `attributes` is refused rather than read as "no number" (§9 item 2). Only attribute names and the
  binding attribute's value are kept; `eppn`, `email`, `external_subject_id` and all other values are
  discarded.
- **Errors.** An unknown service, a `continue_url` that is not `engineblock.return_url_prefix`
  optionally followed by `?…`, or a transaction that cannot be stored answers `{"msg":"error"}`.
- **Decision**, in this order: organisation in the service's `allowed_organisations`
  (`organisation_refused`), no attribute name under `attributes.reserved_prefix`
  (`reserved_attribute`), then the binding attribute `binding.organisation_attribute` (§4): absent,
  `[]` or `[""]` is `skipped`; one non-empty string that is not only whitespace is `pending`;
  anything else is `failed` (`malformed_binding`). Every stored transaction answers
  `{"msg":"interrupt","nonce":…}` with a 256-bit base64url nonce, plus `message`
  `DEZI_LOGIN_REQUIRED` (pending) or `DEZI_SKIPPED` (skipped). A failed transaction gets no `message`;
  its error page is shown at the hand-off.
- **Records.** The nonce is the transaction ID; a separate 16-hex-character log ID is the only
  identifier logged. The deadline is the start time plus `transactions.lifetime_seconds`; a skipped
  transaction's result deadline equals it. `/authz` makes no outgoing request.

**Mock assumptions** stay marked and confined to `mock.yaml`. None is copied into an acceptance or
production configuration without a dated confirmation.

**Health and the startup gate.** `GET /health` is the readiness check: `200
{"status":"UP","certificates":"ok"}` when the configuration passes and the transaction table is reachable and readable,
with `certificates` set to
`expiring` or `expired` within `certificate_expiry_warning_days` (expiry does not stop JIP, design
§14), and `503 {"status":"DOWN"}` otherwise. The database check performs a read without fetching
records or changing the store. It does not verify write privileges or replication health.
Database error details and credentials are never returned. Requests are not gated by container health alone:

- the local mock container runs `jip:config:validate`, then `jip:store:init`, as the web-server user
  before Apache starts and exits if either fails (`devenv/jip/entrypoint.sh`). Production must run
  configuration validation before serving requests and initialize the schema separately with a
  deployment account;
- `Core\Http\ConfigurationGuard` answers `503` on every route except `/health` while the
  configuration fails a check, including on the authentication endpoints.

The guard and handlers use `ConfigurationLoader::load()` to share one validated configuration
snapshot per main HTTP request, including subrequests. Each new request reloads the files; CLI calls
also load afresh. The snapshot is never cached for the lifetime of a persistent worker.

All routes require the API token by default, except `/health`, `/interrupt`, and `/oidc/callback`.

## Browser hand-off and callback

JIP has no credential-entry page. `GET /interrupt?nonce=…` claims a pending transaction atomically,
sets its transaction cookie and redirects to the provider for a fresh login (`prompt=login`,
`max_age=0`, PKCE S256). A skipped transaction returns directly to its validated EngineBlock URL,
without a provider request or cookie. A repeated hand-off for an active attempt shows a progress
page and preserves the attempt.

`GET /oidc/callback?code=…&state=…` requires the attempt's state and matching browser cookie,
then atomically claims the attempt for validation. The cookie is host-only,
named `__Secure-jip_tx_<log_id>`, has `Path=/oidc/callback`, `Secure`, `HttpOnly` and `SameSite=Lax`, and
expires at the transaction deadline (600 seconds after the start in the mock configuration).
A claimed callback clears it after validation, including when validation fails. Separate cookies
allow transactions in different tabs to coexist. Use HTTPS for browser flows; the plain HTTP
health-check command above cannot exercise the Secure cookie.

Error pages show a failure type and, when a transaction is known, its separate log ID. Only these
failure types offer the service's approved `restart_login_url`:

- Core: `expired`, `already_used`, `callback_mismatch`.
- OIDC: `provider_cancelled`, `provider_error`, `discovery_unavailable`,
  `token_request_unavailable`, `key_fetch_unavailable`.
- DEZI profile: `userinfo_unavailable`, `status_check_unavailable`.

The extensions and unknown-link exception to design §§13 and 18 are recorded in
`docs/jip-poc-handover.md`, under “Restart behaviour deviations”.

Other failures are final and direct the user to support. These include `organisation_refused`,
`reserved_attribute`, `malformed_binding`, `service_not_configured`, `invalid_return_url`,
`binding_mismatch`, `required_claim_missing`, `nothing_to_release`,
`callback_invalid`, `discovery_invalid`, `authentication_method_not_supported`,
`client_authentication_refused`, `token_request_refused`, `token_response_invalid`, `key_set_invalid`,
`unknown_key`, `id_token_invalid`, `userinfo_refused`, `userinfo_invalid`, `userinfo_not_decrypted`,
`envelope_invalid`, `statement_invalid`, `statement_not_active`, `statement_unknown`,
`status_request_refused` and `internal_error`. An unknown nonce or state has no known service and therefore
no restart link. Restarting means starting the whole login again, including provider authentication.

After a valid ID token, the callback hands the authenticated login to the configured profile. The
DEZI profile (design §14–§16):

- fetches UserInfo with the access token of this login's token response and decrypts it: a compact
  JWE with `RSA-OAEP` and `A256CBC-HS512` only, without `zip` or `crit`. A configured decryption key
  whose `kid` equals the JWE header's is tried first, then every other configured key in order;
- verifies the envelope with keys from `approved_key_addresses.envelope` only and the statement with
  keys from `approved_key_addresses.statement` only (`RS256`; a supplied `jku` must equal the
  message type's address; the statement must carry it). It checks `iss` per message type, the
  envelope `aud` configured for the client, `iat`, `nbf` and `exp` (numbers only, with the clock skew
  for times in the future but never for expiry), the subject association, `loa_authn` and
  `loa_dezi` per claim, and an equal `verklaring_id` in envelope and statement that is a UUID;
- requires `dezi_nummer` and `abonnee_nummer` as non-empty strings, and every other releasable claim,
  when present, as a non-empty string or a permitted `null` (then absent). Identifiers keep their
  exact format; a profile without `rol_code` gives no role, and `00.000` is kept like any other code;
- checks revocation with one request to `revocation.status_address`, with `{verklaring_id}` replaced.
  The statement's own `status_uri` or `revocatie_controle_uri` is never called. Only HTTP 200 with
  `verklaringId` equal to the statement's and `status` `actief` is active (the §15 names, unconfirmed
  by the CIBG). A `404` is `statement_unknown`, any other 4xx `status_request_refused`; a timeout,
  5xx, redirect or invalid body is `status_check_unavailable`. The decision holds for
  `revocation.decision_validity_seconds`.

The profile hands the core the releasable claims, the hard expiry (the earlier of envelope and
statement `exp`) and the decision for the delivery recheck. The core then requires every claim marked
`required` in `attributes.claims`, compares `binding.claim` with the organisation's number as an
exact string (`binding_mismatch`), keeps only the claims the service releases (`nothing_to_release`
when none is left), and moves the transaction to `succeeded` with a result deadline at the earlier of
the transaction deadline and the hard expiry. The browser then returns to EngineBlock's return URL,
which carries only the SAML request ID. Any failed check moves the transaction to `failed` and shows
its failure type with HTTP 403, with a restart link only for the restartable types above.

Unexpected exceptions during callback validation produce final `internal_error` (HTTP 500), with
the transaction's log ID and no restart link. The callback clears the cookie and records `failed`
when storage is available. If storing that failure also throws, the same safe support page is still
returned, but the transaction cannot be updated. Logs contain the exception class and log ID only;
exception messages and traces are not included.

Discovery and signing-key fetch failures are kept for `provider.key_refetch_min_interval_seconds`
(60 seconds in the mock). Other requests receive the same restartable or final failure type during
that interval, including when no usable document or keys are cached. Fresh keys remain usable after
a failed refetch; expired metadata and keys are never used. The initial fetch still holds the cache
lock for its network request, but queued callers do not each repeat the failed request.

Provider metadata and keys are cached per node under `APP_SHARE_DIR` (`var/share` by default),
separately for each application environment. Keep this directory across deployments; use an absolute
path outside release directories when releases use different paths. `cache:clear` preserves these
entries; invalidate them explicitly with `bin/console cache:pool:clear cache.jip_provider`.
Sharing this cache across nodes also requires a shared lock backend.

All browser responses use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

## `POST /attributes`

EngineBlock's result call (design §12, §13): `{"nonce": …}` in, the attributes out, once.

- **Authentication** as for `/authz`: the raw `Authorization` header must equal
  `engineblock.api_token`; `Authentication` is never read.
- **Answers**, all with `Cache-Control: no-store`:

  | Status | Body | When |
  | --- | --- | --- |
  | `200` | `{"attributes": {<login_flag>: ["verified"], <mapped claims>…}}` | a `succeeded` transaction, with the mapped claims the service releases |
  | `200` | `{"attributes": {<login_flag>: ["skipped"]}}` | a `skipped` transaction; no DEZI attribute |
  | `400` | `{"error":"invalid_request"}` | the body is not JSON |
  | `401` | `{"error":"unauthorized"}` | a missing or wrong `Authorization` header |
  | `403` | `{"error":"forbidden"}` | `pending`, `at_dezi`, `validating` or `failed`; or refused at delivery |
  | `404` | `{"error":"not_found"}` | an unknown or malformed nonce, `consumed`, or past its deadline, also when that passes during the recheck |
  | `500` | `{"error":"internal_error"}` | an unexpected exception; logged by class only |

  A successful answer is never empty: a verified result without any released attribute is refused
  (`nothing_to_release`).
- **Order of checks.** The stored service and organisation against the configured policy; for a
  `succeeded` transaction, the profile's recheck; then the configuration is read again
  (`ConfigurationLoader::reload()`) and service and organisation are checked against that current
  policy immediately before consumption. The connection-policy version at start never grandfathers a
  connection. A refusal (`service_not_configured`, `organisation_refused`, a failed recheck,
  `nothing_to_release`) atomically moves the still-unconsumed transaction to `failed` and answers
  `403`.
- **Recheck (DEZI).** A revocation decision that has expired, or ends within
  `revocation.timeout_seconds`, is renewed with one status check; a valid one needs no request. This
  is the only outgoing request of a result call, and its timeout is at most half of
  `engineblock.call_timeout_seconds`. Renewal never extends the hard expiry: the renewed decision's
  validity is capped by it. A refused or unanswered renewal fails the transaction with its failure
  type.
- **Consumption.** One compare-and-set moves `succeeded` or `skipped` to `consumed` only while the
  transaction is in that state, before its result deadline and before the recheck's validity, all
  checked against the time sampled inside the write lock. Concurrent calls can consume a result only
  once. If the decision's validity ends between the recheck and the write, the transaction fails
  with restartable `expired` (`403`). A consumed transaction keeps no claims and is never delivered
  again; if EngineBlock loses the answer, the user starts a new login.
- **Logging.** The log ID, outcome or failure type, service, organisation, connection-policy version
  at start and at delivery, and EngineBlock's request ID from the return URL. Never the nonce,
  claims or attribute values.

## Logging (design §20)

JIP writes one line per record to PHP's error log, which is the container's error stream
(`Core\Logging\LineLogger`):

| Label | Source | Minimum level |
| --- | --- | --- |
| `jip.<LEVEL>:` | JIP's own messages (start, hand-off, callback, result, startup checks) | `info` |
| `jip.framework.<LEVEL>:` | Symfony (router, HTTP client, uncaught errors). Their info messages name request and provider URLs | `warning` |

Every JIP message starts with `JIP <step> <log_id>`. Messages fill only scalar placeholders, never
write the context, cut the query string from any URL and keep each record on one line. Start,
delivery and callback-failure lines also name the service, the organisation, the connection-policy
version at start (and at delivery), and EngineBlock's request ID: the `ID` of the return URL, only
when it is a plain identifier, otherwise `-`. Failure lines keep the provider-specific detail, for
example `statement_not_active: dezi profile, status check: statement is not active`. Exceptions are
logged by class only.

Tests replace the `jip.logger` service; `when@test` makes both loggers silent.

## Upgrading: the `at_dezi` transaction state

A transaction whose user is at DEZI has the state `at_dezi` (design §13); earlier versions stored
`at_provider`. The state is part of each JSON record in `jip_transactions`, and a record with an
unknown state fails closed: `/interrupt` answers `internal_error` and the callback fails. A node of
either version therefore cannot read the other version's in-flight transactions, and a read alias in
the new version alone would not make a mixed-version deployment safe (older nodes would still fail on
`at_dezi`). Deploy the change in a coordinated way:

1. Stop admitting new logins (no new `POST /authz` reaches JIP).
2. Let the existing transactions finish or expire under their deadlines
   (`transactions.lifetime_seconds`). Expired records are pruned without being decoded.
3. Switch every connector node to the new version together, then admit logins again.

Do not clear stored transactions as a shortcut. The schema is unchanged; `jip:store:init` is not
needed for this change.

## Open before acceptance

- **CIBG answers (design §10).** The acceptance placeholders stay until the CIBG supplies a dated
  confirmation of: the approved key address per message type, the expected issuers, the
  `loa_authn` and `loa_dezi` values, the client ID, `max_age` support, and whether `auth_time` is
  always returned. The client-authentication method is answered: `none` (open client, 13 November
  2026). Only if the CIBG asks for the optional `private_key_jwt` do its signing-key registration and
  assertion contents need answers. The DEZI profile adds: the envelope claim that carries the
  statement (`provider.envelope.statement_claim`), the subject association between UserInfo and the
  ID token (`provider.envelope.subject_association`; `access_token` needs an approved contract), the
  envelope audience per client (`provider.envelope.audiences`), which optional claims may be `null`
  (`provider.statement.nullable_claims`, empty in the template), how a profile without a role is
  represented, and the status response's field names and active value (`verklaringId`, `status`,
  `actief`, taken from §15 and fixed in `RevocationChecker`).
- **Deployment logging (design §20).** The devconf JIP and mock-provider Apache virtual hosts log
  method, path, protocol and status without query strings or headers. Their error-log format also
  omits the `Referer` header that Apache normally appends to PHP log messages. The generated HAProxy log
  includes connection and response metadata only. JIP's logger never writes the request context and
  cuts query strings (see Logging). EngineBlock's stock log is described in `devenv/README.md`.
  Before exercising a flow, verify its Apache, proxy, application and tracing logs
  exclude live SBS nonces, OIDC state/nonces, codes, cookies, tokens, client assertions, sensitive
  payloads and the `Authorization` and `Authentication` headers. Repeat this check whenever logging
  or tracing changes; a new formatter can expose the router's full URI context.

## Keys

Private keys and certificates never enter version control: `keys/`, `*.pem`, `*.key`, `*.p12` and
`*.pfx` are git-ignored.

- **Mock:** `bin/init-mock-keys` creates the decryption key pair (RSA 3072, one year, private keys
  mode 600, directories mode 700) for client `ggd`, which uses `authentication: none`.
  `bin/init-mock-keys --with-signing-key` also creates the signing key pair, needed only for the
  optional `private_key_jwt` setup described in `config/jip/mock.yaml`. It keeps existing files;
  delete `keys/mock/` to start over. The mock DEZI needs the certificates, never the private keys.
  These connector client keys are distinct from the mock DEZI provider's own message-signing keys
  (`mock-dezi/bin/init-keys`), which it always needs.
- **Container access (devconf):** `devenv/bin/setup.sh` runs `bin/init-mock-keys` and grants the
  container's web-server user (`www-data`, uid 33) ACL access only: search (`--x`) on `keys/` and
  `keys/mock/`, read on the key files, and read-write on `var/` with inherited default ACLs. Modes
  stay 600/700, no private key and nothing under `var/` is world-accessible, and nothing is mode 777. Re-run it after creating new
  keys. `devenv/bin/check.sh` verifies the ACLs. The front controllers set umask `027`, because
  Symfony Runtime sets umask `0` in debug mode.
- **Acceptance and production:** the operator places the keys outside the repository (the template
  uses `/etc/jip/keys/`), monitors certificate expiry and follows the replacement orders in design
  §14. The decryption keys are always required and their certificate is registered with the CIBG.
  A signing key, its registration and its rotation apply only with `private_key_jwt`; how DEZI
  registers it is open (design §10).

## Quality checks

```bash
APP_ENV=test composer check  # lint:yaml, lint:container, phpcs, phpstan (level max), deptrac, phpunit, dependency audit
composer run dependency-audit  # dependency audit only, against composer.lock
```

With the local POC containers already running, use these commands from the `jip-dev` repository root:

```bash
devenv/bin/check-container.sh jip           # the same check suite inside the mounted connector container
devenv/bin/check-container.sh jip phpunit   # tests only, using the dedicated jip_test database
```

The wrapper runs as `www-data`, clears the runtime application settings, selects the test environment
and database, and gives the tools writable temporary caches. Container PHP includes `pdo_mysql`, so
the host extension is optional for this workflow. See `devenv/README.md` in `jip-dev` for the environment
overrides and individual check commands.

Configuration for PHP_CodeSniffer (PSR-12 plus the EngineBlock Slevomat rules) and PHPStan is in
`ci/qa-config/`. `devenv/bin/check.sh` also runs `jip:config:validate` on the mock configuration.
Deptrac enforces the dependency direction: Core may use Oidc, profiles may use both, and the shared
configuration readers depend on neither. Oidc must not depend on Core or profiles.
The tests need a MariaDB 10.6 database of their own: `JIP_TEST_DATABASE_*` in `.env.test` points at
jip-dev's `jip-mariadb` (`127.0.0.1:13307`, database `jip_test`); override it in `.env.test.local`.
Every store test drops and recreates the table in that database.

GitHub Actions runs the existing `composer check` suite on pull requests, pushes to `main`, and
every Monday, and supports manual runs. It validates the manifest and lockfile and checks installed
platform requirements. The runner uses PHP 8.5 and Ubuntu 22.04's native MariaDB 10.6 package, with
a dedicated test database; no service container is needed.

Dependabot checks Composer dependencies and GitHub Actions every Monday at 08:00 Europe/Warsaw.
Composer updates stay within the constraints in `composer.json`, including Symfony 7.4; Symfony
version updates and security updates each have their own group. Enable Dependabot alerts and
security updates in the repository's GitHub settings so advisory-driven pull requests can run
independently of the weekly version-update schedule. These files take effect once published to
GitHub; version-update scheduling requires the configuration on the default branch.

The dependency audit needs network access to advisory sources. An unavailable advisory source is a
failed check, not evidence that dependencies are safe. Run the checks after changes and before a
demonstration; investigate reported advisories before continuing affected flows.

## PoC security scope

This PoC uses the local mock environment. The devconf proxy listens on loopback addresses and uses
the development CA. Reassess these decisions before exposing it to other users or using real identity
data. Deferred controls remain open findings, not passed requirements.

- The transaction cookie uses `__Secure-` so supporting browsers require it to be set over HTTPS
  with `Secure`. Its callback-only path is incompatible with the `__Host-` prefix's `Path=/` rule.
- The current SBS and OIDC integration uses GET for `/interrupt` and `/oidc/callback`, with the
  transaction ID, authorization code and state in URLs. The local PoC retains this integration,
  protected by short-lived random values, callback cookie binding, PKCE and atomic state changes.
  Browser responses send `no-store` and `no-referrer`; the local Apache access log omits query strings.
  OIDC supports `form_post`, but provider support, callback handling and cross-site cookie settings
  would need to be checked before switching. It would not remove state from the outgoing
  authorization URL. GET handling and URL exposure remain documented exceptions for this PoC.
- Application responses include `Strict-Transport-Security: max-age=31536000`, including redirects
  and errors. The policy applies to the JIP host; it does not request `includeSubDomains` or preload.
  The header is emitted regardless of the backend connection scheme so it also works behind the
  TLS-terminating proxy; browsers only honor it over trusted HTTPS. Before a non-local deployment,
  verify the externally served TLS certificate and HSTS on all responses, including responses
  generated by the web server or ingress, and check every proxy's logging of query strings and headers.
- Production artifact verification is deferred. Source-control metadata must remain inaccessible
  over HTTP in any hosted PoC; production packaging must omit it or make it inaccessible both to
  external callers and to the application. The `public/` document root alone does not prove this.
- `composer check` audits locked dependencies, including in the weekly CI run. Dependabot provides
  the routine update cadence. Formal risk-based remediation deadlines, an operational owner and an
  exception process remain deferred. A clean audit does not establish compliance with dependency
  update deadlines.
