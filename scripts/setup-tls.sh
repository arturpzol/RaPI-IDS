#!/usr/bin/env bash
# Issue TLS material for the panel: a small local CA, and a server certificate
# signed by it. Idempotent - the CA is created once, the server certificate is
# re-issued whenever it is missing, close to expiry, or no longer covers the
# names this machine answers to.
#
# Why a local CA instead of a bare self-signed certificate: a self-signed one
# makes the browser warn on every visit, and an operator who clicks through that
# warning daily has been trained to ignore exactly the thing it exists for. With
# a CA you import one file once per machine, and re-issuing the server
# certificate later (new address, expiry) needs no further imports.
#
# Not Let's Encrypt: that wants a public domain and reachability from the
# internet, and this device has to work with no route to the outside.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLS_DIR="${RAPI_TLS_DIR:-$ROOT/data/tls}"
CA_KEY="$TLS_DIR/ca.key"
CA_CRT="$TLS_DIR/ca.crt"
SRV_KEY="$TLS_DIR/server.key"
SRV_CRT="$TLS_DIR/server.crt"

CA_DAYS=3650
# 825 days is the longest several browsers accept for a server certificate;
# staying under it keeps the door open if this ever leaves the LAN.
SRV_DAYS=800
# Renew with room to spare rather than on the last day.
RENEW_BEFORE_DAYS=30

command -v openssl >/dev/null || { echo "openssl missing (apt install openssl)" >&2; exit 1; }

mkdir -p "$TLS_DIR"
chmod 0700 "$TLS_DIR"

# --- which names will this box be reached by ---
# The address comes from DHCP, so it is pinned here only as a fallback: prefer
# the mDNS name, which survives a new lease.
collect_names() {
  local host short names=()
  host="$(hostname -f 2>/dev/null || hostname)"
  short="$(hostname)"
  names+=("${short}.local" "$short" "localhost")
  [[ "$host" != "$short" ]] && names+=("$host")
  printf '%s\n' "${names[@]}" | awk 'NF && !seen[$0]++'
}

collect_ips() {
  { ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
    echo 127.0.0.1
  } | awk 'NF && !seen[$0]++'
}

build_san() {
  local i=1 san=""
  while read -r n; do san+="DNS.$i:$n,"; i=$((i + 1)); done < <(collect_names)
  i=1
  while read -r a; do san+="IP.$i:$a,"; i=$((i + 1)); done < <(collect_ips)
  echo "${san%,}"
}

# openssl wants "DNS:a,DNS:b,IP:192.0.2.1"; the numbering above is only used to
# keep the entries distinct while building the list.
san_value() { build_san | sed 's/DNS\.[0-9]*:/DNS:/g; s/IP\.[0-9]*:/IP:/g'; }

SAN="$(san_value)"

# --- certificate authority ---
if [[ -f "$CA_KEY" && -f "$CA_CRT" ]]; then
  echo "==> CA already present: $CA_CRT"
else
  echo "==> Creating the panel CA (valid $CA_DAYS days)"
  openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
  openssl req -x509 -new -key "$CA_KEY" -sha256 -days "$CA_DAYS" -out "$CA_CRT" \
    -subj "/CN=RaPi IDS Panel local CA/O=RaPi IDS Panel" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# --- server certificate ---
needs_issue=0
if [[ ! -f "$SRV_KEY" || ! -f "$SRV_CRT" ]]; then
  needs_issue=1
  reason="no certificate yet"
elif ! openssl x509 -in "$SRV_CRT" -noout -checkend $((RENEW_BEFORE_DAYS * 86400)) >/dev/null 2>&1; then
  needs_issue=1
  reason="expires within $RENEW_BEFORE_DAYS days"
else
  # openssl prints "IP Address:" where it parses "IP:", so both sides have to be
  # normalised before comparing, or the certificate is reissued on every run.
  normalise() { sed 's/IP Address:/IP:/g' | tr -d ' \n' | tr ',' '\n' | sort | paste -sd,; }
  current="$(openssl x509 -in "$SRV_CRT" -noout -ext subjectAltName 2>/dev/null \
    | tail -n +2 | normalise)"
  wanted="$(printf '%s' "$SAN" | normalise)"
  if [[ "$current" != "$wanted" ]]; then
    needs_issue=1
    reason="the addresses of this machine changed"
  fi
fi

if [[ "$needs_issue" -eq 1 ]]; then
  echo "==> Issuing a server certificate ($reason)"
  echo "    names: $SAN"
  openssl ecparam -name prime256v1 -genkey -noout -out "$SRV_KEY"
  openssl req -new -key "$SRV_KEY" -subj "/CN=$(hostname).local/O=RaPi IDS Panel" \
    -out "$TLS_DIR/server.csr"
  openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -CAcreateserial -days "$SRV_DAYS" -sha256 -out "$SRV_CRT" \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$SAN")
  rm -f "$TLS_DIR/server.csr"
else
  echo "==> Server certificate is current, nothing to do"
fi

# Private keys readable only by the panel user. The panel runs unprivileged, so
# it has to own them; nothing else on the box needs to read them.
chmod 0600 "$CA_KEY" "$SRV_KEY"
chmod 0644 "$CA_CRT" "$SRV_CRT"
[[ -n "${SUDO_USER:-}" ]] && chown -R "$SUDO_USER":"$SUDO_USER" "$TLS_DIR"

echo
openssl x509 -in "$SRV_CRT" -noout -subject -enddate -ext subjectAltName | sed 's/^/    /'
echo
echo "Import this file into the browser or system trust store, once per device:"
echo "    $CA_CRT"
echo "Copy it off the Pi with, for example:"
echo "    scp $(whoami)@$(hostname).local:$CA_CRT ."
