# JointIdentityProvider (JIP) proof of concept

JIP connects OpenConext EngineBlock's SBS interface to an external OpenID Connect
identity provider, DEZI, and releases verified attributes. This repository contains
JIP, a mock DEZI provider, a SAML test service provider (SP), and a local development
environment built on OpenConext-devconf.

This is a local proof of concept. DEZI messages and fixtures contain provisional
mock choices; integration with DEZI acceptance has not been verified. See the
[handover](docs/jip-poc-handover.md) for scope and acceptance requirements.

## Repository layout

| Path | Purpose |
| --- | --- |
| [jip/](jip/README.md) | JIP application, configuration and checks |
| [mock-dezi/](mock-dezi/README.md) | Mock DEZI identity provider (IdP), synthetic people and failure scenarios |
| [test-sp/](test-sp/) | SAML SP that demonstrates application access decisions |
| [devenv/](devenv/README.md) | OpenConext development stack, tooling and integration fixtures |
| [docs/jip-poc-handover.md](docs/jip-poc-handover.md) | Demonstrations, resets, verification and open acceptance questions |
| [Design](docs/2026-10-05-high-level-design-dezi-connector.md) | Architecture and requirements |

The local login follows this route:

```text
Test SP → EngineBlock → Mujina organisation IdP → EngineBlock
        → JIP → mock DEZI → JIP → EngineBlock → Test SP
```

OpenConext-devconf supplies the shared infrastructure, including Manage and Mujina.
The local Compose overlay adds JIP, mock DEZI and the test SP. Upstream repositories
and versions are pinned in [devenv/env.dist](devenv/env.dist).

## Prerequisites

The commands below assume a Linux host with Bash. Install:

- Git and OpenSSL 3.
- Docker Engine with Docker Compose 2.24 or newer, accessible to your user.
- PHP 8.5 and Composer 2. Enable `openssl`, `gmp`, `ctype`, `iconv`, `dom` and
  `session`; Composer checks the complete extension requirements for each project.
- The `acl` package, providing `setfacl` and `getfacl` for container access to bind mounts.
- Python 3 with `venv` support for the scripted login tools.

Keep host ports 80 and 443 available for the local proxy. MariaDB uses host port
13306 by default; adjust `DEVCONF_MARIADB_HOST_PORT` in `devenv/.env` if necessary.
Docker also needs a free address pool for the development network. See
[environment prerequisites](devenv/README.md#prerequisites) for details.

## Set up the development environment

Run commands from the repository root unless a different directory is shown.

### 1. Install application and login-tool dependencies

```bash
composer --working-dir=jip install
composer --working-dir=mock-dezi install
composer --working-dir=test-sp install

python3 -m venv devenv/.venv
source devenv/.venv/bin/activate
python3 -m pip install requests beautifulsoup4
```

Activate this virtual environment in each shell where you run the Python tools.

### 2. Prepare upstream code, keys and configuration

```bash
devenv/bin/setup.sh
```

The script fetches the pinned OpenConext-devconf and EngineBlock checkouts under
`devenv/upstream/`, installs EngineBlock's PHP dependencies, creates `devenv/.env`
with an SBS API token, prepares the development CA and proxy configuration, installs
EngineBlock's SBS settings, and generates mock keys with container access permissions.

Check that `devenv/.env` contains `COMPOSE_PROFILES=jip` so the mock provider and
test SP start with the stack. This is the default in `devenv/env.dist`.

### 3. Configure local hostnames and certificate trust

Add these entries to `/etc/hosts` on the machine running your browser, avoiding
duplicates if they already exist:

```text
127.0.0.1 engine.dev.openconext.local engine-api.dev.openconext.local manage.dev.openconext.local mujina-idp.dev.openconext.local profile.dev.openconext.local jip.dev.openconext.local mock-dezi.dev.openconext.local jip-test-sp.dev.openconext.local
::1 engine.dev.openconext.local engine-api.dev.openconext.local manage.dev.openconext.local mujina-idp.dev.openconext.local profile.dev.openconext.local jip.dev.openconext.local mock-dezi.dev.openconext.local jip-test-sp.dev.openconext.local
```

Trust `devenv/certs/openconext-dev-ca.crt` in your browser. On Ubuntu, add it to
the system certificate store with:

```bash
sudo install -m 644 devenv/certs/openconext-dev-ca.crt /usr/local/share/ca-certificates/dezi-openconext-dev-ca.crt
sudo update-ca-certificates
```

Restart the browser. Browsers with a separate certificate store also need the CA
imported there. The proxy binds to loopback; for a remote browser, follow the
[connectivity instructions](devenv/README.md#commands).

### 4. Start and initialize the stack

In terminal 1:

```bash
devenv/bin/compose.sh pull
devenv/bin/compose.sh up
```

Leave it running. In terminal 2, from the repository root:

```bash
(cd devenv/upstream/OpenConext-devconf/core && ./scripts/init.sh)
devenv/bin/compose.sh exec engine bash -c 'cd theme && yarn install --frozen-lockfile && yarn build'
php devenv/bin/manage.php apply
source devenv/.venv/bin/activate
python3 devenv/bin/login-flow.py accounts
devenv/bin/check.sh
php devenv/bin/manage.php audit
```

Initialization prepares the databases and Manage entities. The subsequent commands
build EngineBlock's theme, register the test SP and its policy in Manage, push it
to EngineBlock, and load the synthetic organisation accounts into Mujina.

EngineBlock needs database initialization before it becomes healthy. Use the
attached `up` command for this first start; use `up -d --wait` for later starts.
Read every diagnostic: `check.sh` can exit successfully while reporting `MISSING`
prerequisites. Resolve any `FAIL` from the configuration audit before the login.

## Try the first login

Open [the test SP](https://jip-test-sp.dev.openconext.local/) and choose **Log in**.
At the Mujina organisation IdP, use username `jip-anna` and password `secret`.
At mock DEZI, choose person `anna`. The test SP should grant DEZI access.

The scripted equivalent is:

```bash
source devenv/.venv/bin/activate
python3 devenv/bin/login-flow.py login jip-anna --person anna --expect dezi --show-attributes
```

To demonstrate a login without a DEZI binding, use Mujina account `jip-nonumber`
with password `secret`. It should skip DEZI and receive organisation-level access:

```bash
python3 devenv/bin/login-flow.py login jip-nonumber --expect organisation
```

Organisation accounts are defined in [devenv/mujina/accounts.json](devenv/mujina/accounts.json).
DEZI people and profiles are defined in [mock-dezi/fixtures/profiles.yaml](mock-dezi/fixtures/profiles.yaml).
See the [account catalogue](devenv/README.md#local-integration-design-68-17) and
[mock provider guide](mock-dezi/README.md) for other cases and selectable failures.

## Daily development and verification

```bash
# Start or resume the configured stack.
devenv/bin/compose.sh up -d --wait

# Inspect services and logs.
devenv/bin/compose.sh ps
devenv/bin/compose.sh logs --tail=100 jip mock-dezi jip-test-sp

# Check environment configuration and the test SP's integration policy.
devenv/bin/check.sh
php devenv/bin/manage.php audit

# Stop services while keeping database volumes.
devenv/bin/compose.sh --profile jip stop
```

After a restart, reload Mujina accounts with `python3 devenv/bin/login-flow.py accounts`
if they are missing. Restarting mock DEZI resets its state.

Run the existing application checks with:

```bash
composer --working-dir=jip check
composer --working-dir=mock-dezi check
composer --working-dir=test-sp check
```

For complete flow verification against the running stack, use
`devenv/bin/verify-poc.sh`. It resets mock DEZI state and clears JIP's provider cache;
see [verification details](docs/jip-poc-handover.md#7-repeatable-verification) before running it.
For fixture resets, key regeneration and further demonstrations, use the
[handover](docs/jip-poc-handover.md).
