#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="$1"
BUNDLE_PATH="$2"
HOST_BUNDLE="$3"

mkdir -p "$STATE_DIR" "$(dirname "$BUNDLE_PATH")"
chmod 0700 "$STATE_DIR"
umask 077

credential_dir="${CREDENTIALS_DIRECTORY:-}"
cert_credential=""
key_credential=""
if [[ -n "$credential_dir" ]]; then
  cert_credential="$credential_dir/mitmproxy-ca-cert"
  key_credential="$credential_dir/mitmproxy-ca-key"
fi

regular_credential() {
  local path="$1"
  [[ -n "$path" && -f "$path" && ! -L "$path" ]] || {
    echo "agent-sandbox proxy: credential is not a regular non-symlink file" >&2
    return 1
  }
}

atomic_copy() {
  local source="$1"
  local destination="$2"
  local temporary
  temporary="$(mktemp "${destination}.tmp.XXXXXX")"
  chmod 0600 "$temporary"
  cp -- "$source" "$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$destination"
}

extract_private_key() {
  local source="$1"
  local destination="$2"
  local temporary
  temporary="$(mktemp "${destination}.tmp.XXXXXX")"
  chmod 0600 "$temporary"
  openssl pkey -in "$source" -out "$temporary" >/dev/null 2>&1
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$destination"
}

extract_certificate() {
  local source="$1"
  local destination="$2"
  local temporary
  temporary="$(mktemp "${destination}.tmp.XXXXXX")"
  chmod 0600 "$temporary"
  openssl x509 -in "$source" -out "$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$destination"
}

write_combined_ca() {
  local temporary
  temporary="$(mktemp "${combined_state}.tmp.XXXXXX")"
  chmod 0600 "$temporary"
  cat -- "$key_state" "$cert_state" > "$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$combined_state"
}

validate_ca_pair() {
  local cert="$1"
  local key="$2"
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null
  openssl x509 -in "$cert" -noout -text | grep -Fq 'CA:TRUE'
  openssl x509 -in "$cert" -noout -text | grep -Fq 'Certificate Sign'
  [[ "$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)" == \
    "$(openssl pkey -in "$key" -pubout | openssl pkey -pubin -outform DER | sha256sum)" ]]
}

migrate_legacy_ca() {
  [[ -f "$combined_state" && ! -L "$combined_state" ]] || return 0

  if [[ ! -f "$key_state" || -L "$key_state" ]] ||
    ! openssl pkey -in "$key_state" -pubout >/dev/null 2>&1; then
    extract_private_key "$combined_state" "$key_state"
  fi
  if [[ ! -f "$cert_state" || -L "$cert_state" ]] ||
    ! openssl x509 -in "$cert_state" -noout >/dev/null 2>&1; then
    extract_certificate "$combined_state" "$cert_state"
  fi
}

ensure_dhparam() {
  if [[ -f "$dhparam_state" && ! -L "$dhparam_state" ]] &&
    openssl dhparam -in "$dhparam_state" -check -noout >/dev/null 2>&1; then
    return 0
  fi
  local temporary
  temporary="$(mktemp "${dhparam_state}.tmp.XXXXXX")"
  chmod 0600 "$temporary"
  openssl dhparam -out "$temporary" 2048 >/dev/null 2>&1
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$dhparam_state"
}

cert_state="$STATE_DIR/mitmproxy-ca-cert.pem"
key_state="$STATE_DIR/mitmproxy-ca.key"
combined_state="$STATE_DIR/mitmproxy-ca.pem"
dhparam_state="$STATE_DIR/mitmproxy-ca-dhparam.pem"
if [[ -z "$cert_credential" && -z "$key_credential" ]]; then
  migrate_legacy_ca
fi

if [[ -n "$cert_credential" || -n "$key_credential" ]]; then
  regular_credential "$cert_credential"
  regular_credential "$key_credential"
  atomic_copy "$cert_credential" "$cert_state"
  atomic_copy "$key_credential" "$key_state"
elif [[ ! -f "$cert_state" || -L "$cert_state" || ! -f "$key_state" || -L "$key_state" ]]; then
  temporary_key="$(mktemp "$STATE_DIR/ca-key.XXXXXX")"
  temporary_cert="$(mktemp "$STATE_DIR/ca-cert.XXXXXX")"
  chmod 0600 "$temporary_key" "$temporary_cert"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj '/CN=agent-sandbox interception CA' \
    -addext 'basicConstraints=critical,CA:true,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -keyout "$temporary_key" -out "$temporary_cert" >/dev/null 2>&1
  mv -f -- "$temporary_key" "$key_state"
  mv -f -- "$temporary_cert" "$cert_state"
fi
validate_ca_pair "$cert_state" "$key_state" || {
  echo "agent-sandbox proxy: CA certificate/key failed validation" >&2
  exit 1
}
chmod 0600 "$cert_state" "$key_state"
write_combined_ca
ensure_dhparam

wg_config="$STATE_DIR/wireguard.conf"
if [[ ! -f "$wg_config" || -L "$wg_config" ]]; then
  server_key="$(mktemp "$STATE_DIR/server-key.XXXXXX")"
  client_key="$(mktemp "$STATE_DIR/client-key.XXXXXX")"
  trap 'rm -f "$server_key" "$client_key"' EXIT
  chmod 0600 "$server_key" "$client_key"
  wg genkey > "$server_key"
  wg genkey > "$client_key"
  wg pubkey < "$server_key" >/dev/null
  wg pubkey < "$client_key" >/dev/null
  temporary_config="$(mktemp "$STATE_DIR/wireguard.conf.XXXXXX")"
  chmod 0600 "$temporary_config"
  jq -n --rawfile server_key "$server_key" --rawfile client_key "$client_key" \
    '{server_key: ($server_key | rtrimstr("\n")), client_key: ($client_key | rtrimstr("\n"))}' \
    > "$temporary_config"
  mv -f -- "$temporary_config" "$wg_config"
  rm -f -- "$server_key" "$client_key"
  trap - EXIT
fi
jq -e '(.server_key | type == "string") and (.client_key | type == "string")' "$wg_config" >/dev/null
printf '%s\n' "$(jq -r .server_key "$wg_config")" | wg pubkey >/dev/null
printf '%s\n' "$(jq -r .client_key "$wg_config")" | wg pubkey >/dev/null
chmod 0600 "$wg_config"

# Keep interception trust and host roots in a separate world-readable bundle;
# private keys and the exact WireGuard JSON never leave the private state dir.
temporary_bundle="$(mktemp "${BUNDLE_PATH}.tmp.XXXXXX")"
chmod 0644 "$temporary_bundle"
if [[ -f "$HOST_BUNDLE" ]]; then
  cat -- "$HOST_BUNDLE" > "$temporary_bundle"
fi
cat -- "$cert_state" >> "$temporary_bundle"
chmod 0644 "$temporary_bundle"
mv -f -- "$temporary_bundle" "$BUNDLE_PATH"
