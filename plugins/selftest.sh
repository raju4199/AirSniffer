#!/usr/bin/env bash
#
# Airsniffer plugin self-test
# ===========================
# Static + simulation checks for the Airsniffer plugin suite. Runs anywhere
# (no Wi-Fi hardware/root needed) - catches the classes of bug that bit us
# before (phantom core-variable references, broken syntax, engine regressions,
# menu-id collisions). Run from the repo root:  bash plugins/selftest.sh
#
# Exit code 0 = all green.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

PASS=0
FAIL=0
PY="$(command -v python3 || command -v python)"

ok()   { echo "  [ok]  $*"; PASS=$((PASS+1)); }
bad()  { echo "  [!!]  $*"; FAIL=$((FAIL+1)); }

echo "== 1. bash syntax =="
for f in plugins/*.sh; do
	[ "$f" = "plugins/selftest.sh" ] && continue
	if bash -n "$f" 2>/dev/null; then ok "$f"; else bad "syntax: $f"; fi
done

echo "== 2. python compile =="
for f in plugins/*.py; do
	if "$PY" -m py_compile "$f" 2>/dev/null; then ok "$f"; else bad "compile: $f"; fi
done

echo "== 3. engines run in simulate mode =="
OUT="$(mktemp -d 2>/dev/null || echo /tmp/airsniffer_selftest)"; mkdir -p "$OUT"
run_sim() { if "$PY" "$1" "${@:2}" >/dev/null 2>&1; then ok "sim: $(basename "$1") ${2} ${3:-}"; else bad "sim failed: $(basename "$1") $*"; fi; }
run_sim plugins/fuzzing_dos_engine.py --attack mgmt --mode simulate --seed 1 --logdir "$OUT"
run_sim plugins/fuzzing_dos_engine.py --attack sae --mode simulate --seed 1 --logdir "$OUT"
for s in prehandshake saquery dragondrain badtoken; do
	run_sim plugins/pmf_dos_engine.py --strategy "$s" --mode simulate --seed 1 --count 4 --logdir "$OUT"
done
# recon + mac-acl + portal engines need input; feed a tiny synthetic CSV / POST.
printf '\nBSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\nAA:AA:AA:AA:AA:01, , , 6, 130, WPA2 WPA3 , CCMP , PSK SAE, -50, 100, 0, 0.0.0.0, 3, lab, \n\nStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n11:11:11:11:11:01, , , -40, 10, AA:AA:AA:AA:AA:01, \n' > "$OUT/s.csv"
if "$PY" plugins/recon_triage_engine.py "$OUT/s.csv" >/dev/null 2>&1; then ok "sim: recon_triage_engine"; else bad "recon_triage_engine"; fi
if "$PY" plugins/mac_acl_engine.py "$OUT/s.csv" --bssid "AA:AA:AA:AA:AA:01" >/dev/null 2>&1; then ok "sim: mac_acl_engine"; else bad "mac_acl_engine"; fi
if printf 'key1=abcdefgh&submitBtn=Submit' | "$PY" plugins/portal_verify_engine.py - --ssid lab >/dev/null 2>&1; then ok "sim: portal_verify_engine"; else bad "portal_verify_engine"; fi

echo "== 4. WPA3 menu-id uniqueness =="
dupes="$(grep -hoE '_menu_string_id=[0-9]+' plugins/*.sh | sort | uniq -d)"
if [ -z "$dupes" ]; then ok "no duplicate menu string ids"; else bad "duplicate menu ids: $dupes"; fi

echo "== 5. phantom core-variable references =="
# A ${var} a plugin reads is a phantom unless it is assigned somewhere the
# runtime will actually see it: in that plugin (any form), or in the core
# airsniffer.sh. ALL-CAPS names are treated as external env vars. This is the
# exact class of bug that made the Fuzzing DoS 'sta' direction a no-op
# (clients_bssid never existed in the core). Run as one fast Python pass.
if "$PY" -I - <<'PHANTOM'
import re, sys, glob
core = open("airsniffer.sh", encoding="utf-8", errors="replace").read()
def assigned(s, v):
    ev = re.escape(v)
    pats = [(r'(^|[^A-Za-z0-9_])%s=' % ev, re.M),
            (r'declare\s+-[A-Za-z]+\s+%s\b' % ev, 0),
            (r'\bread\b[^\n]*\b%s\b' % ev, 0),
            (r'printf -v %s\b' % ev, 0),
            (r'\bfor %s \b' % ev, 0),
            (r'\bwhile\b[^\n]*\b%s\b' % ev, 0)]
    return any(re.search(p, s, f) for p, f in pats)
safe = {"PATH", "BASH_SOURCE", "IFS", "HOME", "PWD", "RANDOM"}
fails = 0
for plug in sorted(glob.glob("plugins/*.sh")):
    if plug.endswith("selftest.sh"):
        continue
    src = open(plug, encoding="utf-8", errors="replace").read()
    for v in sorted(set(re.findall(r'\$\{([A-Za-z_][A-Za-z0-9_]*)', src))):
        if v in safe or v.endswith("_color"):
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", v):   # external env var convention
            continue
        if assigned(src, v) or assigned(core, v):
            continue
        print("  [!!]  %s: phantom ${%s}" % (plug, v))
        fails += 1
sys.exit(1 if fails else 0)
PHANTOM
then ok "no phantom core-variable references"; else bad "phantom core-variable reference(s) found"; fi

echo
echo "== summary: ${PASS} passed, ${FAIL} failed =="
rm -rf "$OUT" 2>/dev/null
[ "$FAIL" -eq 0 ]
