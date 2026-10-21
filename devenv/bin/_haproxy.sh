# Shared rendering and validation for the POC's credential-free proxy logs.

jip_haproxy_logging_is_safe() {
    awk '
        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line ~ /^option[[:space:]]+httplog([[:space:]]|$)/) unsafe = 1
            if (line ~ /^log-format([[:space:]]|$)/) {
                if (line != "log-format \"%ci:%cp [%t] %ft %b/%s %ST %B\"") unsafe = 1
                seen = 1
            }
        }
        END { exit (unsafe || !seen) }
    ' "$1"
}

jip_render_haproxy() {
    local base="$1" overlay="$2" output="$3" rendered
    rendered=$(mktemp "${output}.XXXXXX") || return 1
    if ! { cat "$base" && echo && cat "$overlay"; } \
        | sed 's/^[[:space:]]*option[[:space:]]*httplog[[:space:]]*$/    log-format "%ci:%cp [%t] %ft %b\/%s %ST %B"/' \
        > "$rendered"; then
        rm -- "$rendered"
        return 1
    fi
    if ! jip_haproxy_logging_is_safe "$rendered"; then
        echo "HAProxy logging is unsafe or unsupported; refusing to publish the generated configuration." >&2
        rm -- "$rendered"
        return 1
    fi
    # Keep the output inode: the existing container bind-mounts this file.
    cat "$rendered" > "$output"
    local result=$?
    rm -- "$rendered"
    return "$result"
}
