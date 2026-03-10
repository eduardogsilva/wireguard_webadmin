#!/bin/sh

set -eu

MANUAL_CERT_DIR="${MANUAL_CERT_DIR:-/certificates}"
CADDYFILE_PATH="${CADDYFILE_PATH:-/etc/caddy/Caddyfile}"

trim_value() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

is_valid_hostname() {
    host_value="$1"

    if [ -z "$host_value" ]; then
        return 1
    fi

    if is_ip_host "$host_value"; then
        return 1
    fi

    if printf '%s' "$host_value" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'; then
        return 0
    fi

    return 1
}

is_ip_host() {
    host_value="$1"

    case "$host_value" in
        \[*\]|*:*:*)
            return 0
            ;;
        *)
            ;;
    esac

    if printf '%s' "$host_value" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        return 0
    fi

    return 1
}

is_internal_tls_host() {
    host_value="$1"

    case "$host_value" in
        localhost|*.localhost)
            return 0
            ;;
    esac

    if is_ip_host "$host_value"; then
        return 0
    fi

    return 1
}

normalize_host() {
    raw_value="$(trim_value "$1")"
    raw_value="${raw_value#http://}"
    raw_value="${raw_value#https://}"
    raw_value="${raw_value%%/*}"

    case "$raw_value" in
        \[*\]:*)
            printf '%s' "${raw_value%:*}"
            ;;
        *:*)
            case "$raw_value" in
                *:*:*)
                    printf '%s' "$raw_value"
                    ;;
                *)
                    printf '%s' "${raw_value%%:*}"
                    ;;
            esac
            ;;
        *)
            printf '%s' "$raw_value"
            ;;
    esac
}

append_host() {
    candidate_host="$(normalize_host "$1")"

    if [ -z "$candidate_host" ]; then
        return
    fi

    case "
$HOSTS
" in
        *"
$candidate_host
"*)
            return
            ;;
    esac

    if [ -z "$HOSTS" ]; then
        HOSTS="$candidate_host"
        return
    fi

    HOSTS="$HOSTS
$candidate_host"
}

append_dns_host() {
    candidate_host="$(normalize_host "$1")"

    if [ -z "$candidate_host" ]; then
        return
    fi

    if is_internal_tls_host "$candidate_host"; then
        return
    fi

    append_host "$candidate_host"
}

build_common_block() {
    cat <<'EOF'
    import wireguard_common
EOF
}

build_tls_block() {
    domain_name="$1"
    cert_file="${MANUAL_CERT_DIR}/${domain_name}/fullchain.pem"
    key_file="${MANUAL_CERT_DIR}/${domain_name}/key.pem"

    if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
        cat <<EOF
    tls ${cert_file} ${key_file}
EOF
        return
    fi

    if is_internal_tls_host "$domain_name"; then
        cat <<'EOF'
    tls internal
EOF
        return
    fi

    cat <<'EOF'
    tls {
        issuer acme
        issuer internal
    }
EOF
}

HOSTS=""
PRIMARY_HOST="$(normalize_host "${SERVER_ADDRESS:-}")"

if ! is_valid_hostname "$PRIMARY_HOST"; then
    echo "SERVER_ADDRESS must be a hostname, not an IP address. Received: ${SERVER_ADDRESS:-}"
    exit 1
fi

append_host "$PRIMARY_HOST"

ORIGINAL_IFS="$IFS"
IFS=','
for configured_host in ${EXTRA_ALLOWED_HOSTS:-}; do
    append_dns_host "$configured_host"
done
IFS="$ORIGINAL_IFS"

if [ -z "$HOSTS" ]; then
    echo "No valid hostnames were provided for Caddy."
    exit 1
fi

mkdir -p "$(dirname "$CADDYFILE_PATH")"

cat > "$CADDYFILE_PATH" <<'EOF'
(wireguard_common) {
    encode gzip

    @static path /static/*
    handle @static {
        root * /static
        uri strip_prefix /static
        file_server
        header Cache-Control "public, max-age=3600"
    }

    handle {
        reverse_proxy wireguard-webadmin:8000 {
            header_up Host {host}
        }
    }
}
EOF

printf '%s\n' "$HOSTS" | while IFS= read -r current_host; do
    if [ -z "$current_host" ]; then
        continue
    fi

    {
        printf '\n%s {\n' "$current_host"
        build_common_block
        build_tls_block "$current_host"
        printf '}\n'
    } >> "$CADDYFILE_PATH"
done

if command -v caddy >/dev/null 2>&1; then
    caddy fmt --overwrite "$CADDYFILE_PATH" >/dev/null 2>&1
fi

exec "$@"
