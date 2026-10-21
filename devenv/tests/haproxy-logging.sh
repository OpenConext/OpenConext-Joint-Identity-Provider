#!/usr/bin/env bash
# No containers: exercise the renderer and the guard shared by setup.sh and check.sh.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../bin/_haproxy.sh"
review_dir=$(mktemp -d)
trap 'rm -r -- "$review_dir"' EXIT
printf '\nbackend jip_be\n' > "$review_dir/overlay"

for directive in 'option httplog' $' \toption\t httplog  '; do
    printf 'defaults\n    %s\n' "$directive" > "$review_dir/base"
    jip_render_haproxy "$review_dir/base" "$review_dir/overlay" "$review_dir/generated"
    jip_haproxy_logging_is_safe "$review_dir/generated"
    grep -q '^backend jip_be$' "$review_dir/generated"
done
cp "$review_dir/generated" "$review_dir/previous"

for directive in 'option httplog # upstream comment' 'option httplog clf' \
    'log-format "%r"' 'log-format "%{+Q}r"' 'option tcplog'; do
    printf 'defaults\n    %s\n' "$directive" > "$review_dir/base"
    if jip_render_haproxy "$review_dir/base" "$review_dir/overlay" "$review_dir/generated" 2>/dev/null; then
        echo "FAIL: renderer accepted unsupported logging" >&2
        exit 1
    fi
    cmp "$review_dir/previous" "$review_dir/generated"
done

# A second active format must not override the approved one; comments are harmless.
for directive in 'log-format "%r"' 'option httplog clf'; do
    cp "$review_dir/previous" "$review_dir/unsafe"
    printf '    %s\n' "$directive" >> "$review_dir/unsafe"
    if jip_haproxy_logging_is_safe "$review_dir/unsafe"; then exit 1; fi
done
printf '# option httplog\n' >> "$review_dir/generated"
jip_haproxy_logging_is_safe "$review_dir/generated"
echo 'HAProxy logging regression checks passed.'
