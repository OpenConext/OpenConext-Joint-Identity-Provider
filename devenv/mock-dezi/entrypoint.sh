#!/usr/bin/env bash
# Entrypoint of the mock DEZI provider container in devconf. Like devenv/jip/entrypoint.sh, it replaces the base
# image's /entrypoint.sh, which clears the cache as root and makes var/cache and var/log mode 1777.
# Starting the container resets the mock's state (logins, codes, tokens, scenario and endpoint selections).
set -euo pipefail

# shellcheck disable=SC1091
source /etc/apache2/envvars
export HTTPD_CSP="${HTTPD_CSP-}"

cd /var/www/html

as_web_user() { runuser -u "${APACHE_RUN_USER}" -- "$@"; }
as_web_user php bin/console cache:clear --no-interaction --quiet
if ! as_web_user php bin/console mock-dezi:reset --no-interaction --no-ansi; then
    echo "mock DEZI provider: configuration, fixtures or keys unusable; Apache is not started." >&2
    exit 1
fi

exec "$@"
