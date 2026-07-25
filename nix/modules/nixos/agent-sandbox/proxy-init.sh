#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="$1"
BUNDLE_PATH="$2"
HOST_BUNDLE="$3"
ECH_INIT_BIN="$4"

mkdir -p "$STATE_DIR" "$(dirname "$BUNDLE_PATH")"
chmod 0700 "$STATE_DIR"
umask 077

credential_dir="${CREDENTIALS_DIRECTORY:-}"
cert_credential=""
key_credential=""

if [[ -n "$credential_dir" ]]; then
  cert_credential="$credential_dir/proxy-ca-cert"
  key_credential="$credential_dir/proxy-ca-key"
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

validate_ca_pair() {
  local cert="$1"
  local key="$2"
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null
  openssl x509 -in "$cert" -noout -text | grep -Fq 'CA:TRUE'
  openssl x509 -in "$cert" -noout -text | grep -Fq 'Certificate Sign'

  [[ "$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)" == \
    "$(openssl pkey -in "$key" -pubout | openssl pkey -pubin -outform DER | sha256sum)" ]]
}

cert_state="$STATE_DIR/proxy-ca-cert.pem"
key_state="$STATE_DIR/proxy-ca.key"

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
temporary_bundle="$(mktemp "${BUNDLE_PATH}.tmp.XXXXXX")"
chmod 0644 "$temporary_bundle"

if [[ -f "$HOST_BUNDLE" ]]; then
  cat -- "$HOST_BUNDLE" > "$temporary_bundle"
fi

cat -- "$cert_state" >> "$temporary_bundle"
chmod 0644 "$temporary_bundle"

mv -f -- "$temporary_bundle" "$BUNDLE_PATH"

"$ECH_INIT_BIN" --init-ech-state-only --ech-state-dir "$STATE_DIR"

