#!/usr/bin/env bash
# Entrypoint of the JIP container in devconf. It replaces the base image's /entrypoint.sh, which clears
# the cache as root and makes var/cache and var/log mode 1777 on the bind-mounted code.
set -euo pipefail

# shellcheck disable=SC1091
source /etc/apache2/envvars
export HTTPD_CSP="${HTTPD_CSP-}"

if [[ -e /config/haproxy/haproxy.crt ]]; then
    cp /config/haproxy/haproxy.crt /usr/local/share/ca-certificates/
    update-ca-certificates >/dev/null
fi

cd /var/www/html

# Startup gate (design §17): run as the web-server user, so key and var/ access are checked as well.
as_web_user() { runuser -u "${APACHE_RUN_USER}" -- "$@"; }
as_web_user php bin/console cache:clear --no-interaction --quiet
if ! as_web_user php bin/console jip:config:validate --no-interaction --no-ansi; then
    echo "JIP: the configuration fails the startup checks; Apache is not started." >&2
    exit 1
fi

exec "$@"
