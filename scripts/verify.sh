#!/usr/bin/env bash
# Acceptance test for a running sensor. Answers one question that no counter on
# any screen answers on its own: is this device actually detecting anything?
#
#   scripts/verify.sh
#
# Every serious fault this project has had looked identical from the outside.
# The service was active, packets were counted, alerts were arriving, and one
# of these was true anyway:
#
#   * the sandbox stopped the panel using sudo, so silenced signatures came
#     back on the next rule rebuild and nothing said so,
#   * the capture ring was 256 packets deep and 13 % of traffic was dropped
#     before inspection,
#   * the VLAN id was part of the flow key, so every conversation arrived as
#     two unidirectional halves, no TCP session was ever established, no
#     app-layer parser ever started, and every rule matching a server's reply
#     was dead. Twelve hours: 12 179 TCP flows, one of them bidirectional,
#     zero tls and zero http.
#
# 476 unit tests pass in the presence of all three, because they test code in
# isolation. This puts traffic on the wire and asks what came out the other end.
#
# Exit 0 everything checked passed, 1 something failed, 2 nothing failed but a
# check could not be run.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YAML="${RAPI_SURICATA_YAML:-/etc/suricata/suricata.yaml}"
DATA_DIR="${RAPI_DATA_DIR:-$ROOT/data}"
CAPTURE_YAML="${RAPI_SURICATA_CAPTURE:-/etc/suricata/rapi-capture.yaml}"
HOME_NET_STATE="${RAPI_HOME_NET_STATE:-/etc/suricata/rapi-home-net}"
RULES="${RAPI_RULES_FILE:-/var/lib/suricata/rules/suricata.rules}"
PROBE="${RAPI_CAPTURE_PROBE_BIN:-/usr/local/sbin/rapi-capture-probe}"

# Whether the engine reads a copy of the traffic (a mirror port, a tap, this
# device alone) or stands in the link itself (the inline bridge, or the pair it
# forwards in blocking mode). The checks are the same questions; the words for
# what is wrong are not. Telling somebody whose cables run through the Pi to
# check their mirror sends them looking for a switch setting their layout does
# not use. Read from the file the engine is configured from, like everything
# else here.
LAYOUT=copy
if grep -qE '^[[:space:]]*-[[:space:]]*interface:[[:space:]]*br-rapi[[:space:]]*$' \
     "$CAPTURE_YAML" 2>/dev/null \
   || grep -qE '^[[:space:]]*copy-mode:[[:space:]]*ips' "$CAPTURE_YAML" 2>/dev/null; then
  LAYOUT=inline
fi

# A mirror hands over bursts at line rate whatever the average is, so a little
# loss is normal and a lot is a ring that is too small. Between the two there is
# no honest place to draw a line; this one is drawn where the last fault was
# forty times worse than it.
MAX_DROP_PERCENT=1
# Below this many TCP flow records there is not enough traffic to say anything
# about direction, and claiming otherwise on an idle network would be a lie.
MIN_FLOWS=20
PROBE_SECONDS=8
# How long to wait for a test request to come back as an alert. The engine sees
# it on the mirror, writes it, and the tailer picks it up; six seconds is the
# whole path several times over.
ALERT_TIMEOUT="${RAPI_VERIFY_ALERT_TIMEOUT:-15}"
# ET ADWARE_PUP Fake Wget User-Agent. Chosen because of what it needs to fire:
# an established TCP session, a working HTTP parser, and a source inside
# HOME_NET talking to something outside it. A rule that matches a single packet
# would prove none of that - and that is not hypothetical, the check we used to
# do by hand fired GPL 2100498, which is `alert ip any any -> any any` with a
# bare content match and would pass on a sensor that sees nothing else at all.
#
# The destination is deliberately ordinary. The rule is
#   alert http $HOME_NET any -> $EXTERNAL_NET any ... http.user_agent
# so what it needs is any plain-HTTP request to anything outside HOME_NET; the
# far end neither knows nor matters. It used to point at testmynids.org, which
# went away - NXDOMAIN from four independent resolvers on 2026-09-01, Cloudflare
# and Quad9 among them - and took the only check that proves anything with it.
# A release gate that depends on somebody else's domain still being registered
# is not a gate. This one answers over plain HTTP because apt needs it to.
TEST_SID=2007961
TEST_AGENT="wget 3.0"
TEST_URL="${RAPI_VERIFY_URL:-http://deb.debian.org/debian/}"

pass=0; fail=0; skip=0
ok()      { printf '  \033[32mok\033[0m    %s\n' "$1"; pass=$((pass + 1)); }
bad()     { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail + 1)); }
unknown() { printf '  \033[33m?\033[0m     %s\n' "$1"; skip=$((skip + 1)); }
note()    { printf '        %s\n' "$1"; }
head2()   { printf '\n%s\n' "$1"; }

counters() {
  sudo -n suricatasc -c dump-counters 2>/dev/null
}

log_dir() {
  suricata --dump-config -c "$YAML" 2>/dev/null \
    | sed -n 's/^default-log-dir = //p' | tail -1
}

EVE=""
DIR="$(log_dir)"
[[ -n "$DIR" && -f "${DIR%/}/eve.json" ]] && EVE="${DIR%/}/eve.json"
COUNTERS="$(counters)"

# --- 1. the engine is running and inspecting -------------------------------
head2 "1. Capture"
if ! systemctl is-active --quiet suricata; then
  bad "the engine is not running"
elif [[ -z "$COUNTERS" ]]; then
  unknown "cannot read the engine counters (needs sudo suricatasc)"
else
  read -r packets drops has_capture decoded <<<"$(printf '%s' "$COUNTERS" | python3 -c '
import json, sys
m = json.load(sys.stdin)["message"]
c = m.get("capture", {})
print(c.get("kernel_packets", 0), c.get("kernel_drops", 0), int(bool(c)),
      m.get("decoder", {}).get("pkts", 0))')"
  # On a netfilter queue there is no ring and no capture section at all, and
  # reading the missing section as zero packets failed a working sensor.
  if (( has_capture == 0 && decoded > 0 )); then
    unknown "$decoded packets inspected; capture loss is not reported on a netfilter queue"
  elif (( packets == 0 )); then
    bad "no packets have reached the engine at all"
    note "the capture interface is down, or the switch is not mirroring to it"
  else
    percent=$(( drops * 100 / packets ))
    if (( percent > MAX_DROP_PERCENT )); then
      bad "$drops of $packets packets dropped before inspection (${percent}%)"
      note "a dropped packet is not inspected, so the alert inside it never happens"
      note "raise ring-size in $CAPTURE_YAML"
    else
      ok "$packets packets, $drops dropped (${percent}%)"
    fi
  fi
fi

# --- 2. the traffic of other machines really arrives -------------------------
if [[ "$LAYOUT" == inline ]]; then
  head2 "2. Traffic crosses the link"
else
  head2 "2. Mirror port"
fi
IFACES="$(printf '%s' "$COUNTERS" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)["message"]
except Exception:
    raise SystemExit
print(" ".join(k for k in d if k not in ("uptime",) and isinstance(d[k], dict)
                and "capture" in d[k]))' 2>/dev/null)"
IFACE="${IFACES%% *}"
[[ -z "$IFACE" ]] && IFACE="$(sed -n 's/^\s*- interface:\s*\(\S*\)\s*$/\1/p' \
  "$CAPTURE_YAML" 2>/dev/null | head -1)"

if [[ -z "$IFACE" || "$IFACE" == "default" ]]; then
  unknown "cannot tell which interface the engine is capturing on"
elif [[ ! -x "$PROBE" ]]; then
  unknown "rapi-capture-probe is not installed"
else
  # The path spelled out, not "$PROBE": sudoers grants this exact command, and
  # a variable here would hide which privilege the gate asks for.
  FOREIGN="$(sudo -n /usr/local/sbin/rapi-capture-probe "$IFACE" "$PROBE_SECONDS" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("foreign_unicast", 0))' 2>/dev/null)"
  if [[ -z "$FOREIGN" ]]; then
    unknown "the probe did not answer"
  elif (( FOREIGN == 0 )); then
    bad "no frames addressed to other machines arrived on $IFACE in ${PROBE_SECONDS}s"
    if [[ "$LAYOUT" == inline ]]; then
      note "no conversation crossed the link while it listened"
      note "check that both cables carry traffic, or that anything is talking"
    else
      note "on a switched network that means the sensor is watching itself"
    fi
  else
    ok "$FOREIGN frames addressed to other machines on $IFACE"
  fi
fi

# --- 3. both directions of a conversation arrive ---------------------------
head2 "3. Both directions"
# Only what the engine now running has seen. The file outlives restarts, and
# answering with traffic from before the last configuration change would report
# a fault that has already been fixed - or hide one that has just been made.
SINCE=""
if [[ -n "$COUNTERS" ]]; then
  SINCE="$(printf '%s' "$COUNTERS" | python3 -c '
import datetime, json, sys
up = json.load(sys.stdin)["message"].get("uptime", 0)
start = datetime.datetime.now().astimezone() - datetime.timedelta(seconds=up)
print(start.isoformat())')"
fi
if [[ -z "$EVE" ]]; then
  unknown "no eve.json to read (log directory: ${DIR:-unknown})"
else
  read -r total both <<<"$(python3 "$ROOT/scripts/lib/eve-flows.py" "$EVE" "$SINCE")"
  if (( total < MIN_FLOWS )); then
    unknown "only $total TCP flow records since the engine started - not enough to judge"
  elif (( both * 2 < total )); then
    bad "$both of $total TCP flows had traffic in both directions"
    note "each conversation is arriving as two halves that never meet"
    note "usual cause: the VLAN id is in the flow key. See vlan.use-for-tracking"
  else
    ok "$both of $total TCP flows had traffic in both directions"
  fi
fi

# --- 4. the application layer is being parsed ------------------------------
head2 "4. Application layer"
if [[ -z "$COUNTERS" ]]; then
  unknown "cannot read the engine counters"
else
  read -r sessions tls http <<<"$(printf '%s' "$COUNTERS" | python3 -c '
import json, sys
d = json.load(sys.stdin)["message"]
flow = d.get("app_layer", {}).get("flow", {})
print(d.get("tcp", {}).get("sessions", 0), flow.get("tls", 0), flow.get("http", 0))')"
  if (( sessions == 0 )); then
    unknown "no TCP sessions yet - nothing to parse"
  elif (( tls == 0 && http == 0 )); then
    bad "$sessions TCP sessions and not one tls or http flow among them"
    note "no session is being established, so no parser ever starts"
    note "every rule that matches on what a server sends back is dead"
  else
    ok "$sessions TCP sessions, $tls tls and $http http flows parsed"
  fi
fi

# --- 5. a real request comes back as an alert ------------------------------
head2 "5. Detection, end to end"
if [[ -z "$EVE" ]]; then
  unknown "no eve.json to watch"
elif ! command -v curl >/dev/null; then
  unknown "curl is not installed"
else
  BEFORE=$(grep -ac "\"signature_id\":$TEST_SID" "$EVE"); BEFORE=${BEFORE:-0}
  # -4 deliberately. HOME_NET is a list of IPv4 networks, so the same request
  # over IPv6 comes from an address the rule does not consider inside, and the
  # check would fail for a reason that has nothing to do with what it tests.
  # That is not hypothetical: this host resolves the test name to IPv6 first.
  REMOTE=$(curl -4 -s -m 10 -A "$TEST_AGENT" -o /dev/null -w '%{remote_ip}' "$TEST_URL")
  if [[ -z "$REMOTE" ]]; then
    unknown "could not reach $TEST_URL over IPv4 - no way to generate test traffic"
  else
    FOUND=0
    for _ in $(seq "$ALERT_TIMEOUT"); do
      AFTER=$(grep -ac "\"signature_id\":$TEST_SID" "$EVE"); AFTER=${AFTER:-0}
      if (( AFTER > BEFORE )); then FOUND=1; break; fi
      sleep 1
    done
    if (( FOUND == 1 )); then
      ok "a request from this machine came back as SID $TEST_SID"
      note "that needed an established session, a working HTTP parser,"
      note "and this machine to be inside HOME_NET"
    else
      # Two very different faults look the same here, so ask which one it is
      # rather than reporting the wrong one. If the engine never saw the
      # packets, nothing is broken - this machine's uplink simply is not on the
      # segment being mirrored, which is the normal case for a sensor with a
      # separate management network.
      SEEN=$(grep -ac "\"$REMOTE\"" "$EVE"); SEEN=${SEEN:-0}
      if (( SEEN == 0 )); then
        unknown "this machine's own traffic does not reach the sensor"
        note "the request went to $REMOTE and the engine never saw a packet of it"
        if [[ "$LAYOUT" == inline ]]; then
          # The panel is reached another way on this layout, on purpose, so its
          # own requests never cross the link being inspected.
          note "run this from a machine behind the link instead:"
        else
          note "run this from a machine on the mirrored segment instead:"
        fi
        note "  curl -4 -A '$TEST_AGENT' $TEST_URL"
      else
        bad "the engine saw the request to $REMOTE but raised no alert"
        note "the detection chain is broken past capture. Checks 3, 4 and 6"
        note "say which part - session, parser, or HOME_NET"
      fi
    fi
  fi
fi

# --- 6. the sensor is inside the networks it calls inside ------------------
head2 "6. HOME_NET"
# Most of the rule set is written as $HOME_NET -> $EXTERNAL_NET or the reverse.
# A sensor watching a segment that is not in HOME_NET loads all 68 556 rules,
# reports itself healthy, and most of them can never match. Nothing warns.
if [[ -z "$EVE" ]]; then
  unknown "no eve.json to read"
elif [[ ! -f "$HOME_NET_STATE" ]]; then
  unknown "HOME_NET has not been set by the panel"
else
  read -r seen inside <<<"$(python3 "$ROOT/scripts/lib/eve-homenet.py" \
    "$EVE" "$(cat "$HOME_NET_STATE")" "$SINCE")"
  if (( seen < MIN_FLOWS )); then
    unknown "only $seen flow records since the engine started - not enough to judge"
  elif (( inside * 2 < seen )); then
    bad "$inside of $seen flows had an endpoint inside HOME_NET"
    note "most of the rule set is written as HOME_NET -> EXTERNAL_NET,"
    note "so on this segment most of it can never match"
    note "HOME_NET is $(cat "$HOME_NET_STATE")"
  else
    ok "$inside of $seen flows had an endpoint inside HOME_NET"
  fi
fi

# --- 7. what the panel silenced is really silent ---------------------------
head2 "7. Silenced signatures"
DISABLE="$DATA_DIR/disable.conf"
if [[ ! -f "$DISABLE" ]]; then
  unknown "no disable.conf at $DISABLE"
elif [[ ! -f "$RULES" ]]; then
  unknown "no merged rule file at $RULES"
else
  # This is the check that catches the whole "reports success, does nothing"
  # family. suricata-update exits 0 when it cannot read disable.conf, and the
  # panel reported a successful rebuild while every silenced signature came
  # back - for three days, because /home/rapi is 0700 and root in the panel's
  # sandbox lacked CAP_DAC_READ_SEARCH.
  STILL_ON=""
  while read -r sid; do
    [[ -z "$sid" ]] && continue
    # Alert or drop: with blocking on, every rule in an enabled category is
    # loaded as drop, and a silenced one still loaded that way passed this
    # check while it went on alerting and stopping traffic.
    if grep -aqE "^(alert|drop) .*sid:$sid;" "$RULES"; then
      STILL_ON="$STILL_ON $sid"
    fi
  done < <(grep -aE '^[0-9]+$' "$DISABLE")

  if [[ -n "$STILL_ON" ]]; then
    bad "signatures the panel silenced are still enabled:$STILL_ON"
    note "the rebuild reported success and did not read $DISABLE"
  else
    ok "every silenced signature is out of the rule set"
  fi

  if grep -aq '^metadata: signature_severity Informational' "$DISABLE"; then
    LEFT=$(grep -acE '^(alert|drop) .*signature_severity Informational' "$RULES"); LEFT=${LEFT:-0}
    TOTAL=$(grep -acE 'signature_severity Informational' "$RULES"); TOTAL=${TOTAL:-0}
    # Not zero: suricata-update re-enables rules that others depend on through
    # flowbits, and that is correct - a rule set with the dependency missing
    # would quietly stop the dependent rule firing too.
    if (( TOTAL > 0 && LEFT * 20 > TOTAL )); then
      bad "informational is switched off but $LEFT of $TOTAL such rules are loaded"
    else
      ok "informational is off: $LEFT of $TOTAL such rules loaded (flowbit dependencies)"
    fi
  fi
fi

# --- verdict ----------------------------------------------------------------
printf '\n%s\n' "$pass passed, $fail failed, $skip could not be checked"
if (( fail > 0 )); then
  echo "This sensor is not detecting everything it appears to be."
  exit 1
fi
if (( skip > 0 )); then
  echo "Nothing failed, but not everything could be checked."
  exit 2
fi
echo "The detection chain works end to end."
