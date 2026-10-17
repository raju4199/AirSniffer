#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Airsniffer - MAC ACL (filter) bypass helper
============================================

MAC filtering is a weak access control: an AP that only permits a whitelist of
client MACs can be bypassed by impersonating a MAC that is already allowed. The
already-allowed MACs are exactly the clients observed *associated* to the target
in a passive scan - so this helper reads an ``airodump-ng`` CSV and lists the
candidate MACs to spoof for a given target BSSID, with a presence hint so the
operator can prefer a client that looks offline (impersonating one that is
currently online can cause an address conflict and tips off the target).

This helper is passive: it only reads a capture. The actual MAC change and the
connection attempt are done by the bash plugin, behind an authorization gate.

AUTHORIZED USE ONLY.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

# Reuse the airodump CSV parser from the recon triage engine (same directory).
try:
    from recon_triage_engine import parse_csv
except ImportError:  # pragma: no cover - only if run from another cwd
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from recon_triage_engine import parse_csv


def normalise_mac(mac: str) -> str:
    return mac.strip().upper()


def presence_hint(power: int) -> str:
    """airodump power is negative dBm; -1/-100 usually means 'not heard now'.
    A strong signal means the real client is present - a riskier MAC to clone."""
    if power <= -100 or power == -1:
        return "likely offline (safe to clone)"
    if power > -60:
        return "ONLINE now (strong) - clone only if it leaves"
    if power > -75:
        return "possibly online (medium)"
    return "weak/intermittent"


def find_candidates(text: str, bssid: str) -> dict:
    aps, stations = parse_csv(text)
    target = normalise_mac(bssid)

    ap = None
    for b, a in aps.items():
        if normalise_mac(b) == target:
            ap = a
            break

    # Build the candidate list from stations associated to the target. Fall back
    # to the AP's own client list if the station rows lack power data.
    candidates = []
    assoc_macs = {normalise_mac(m) for m in (ap.clients if ap else [])}
    for st in stations:
        if normalise_mac(st.bssid) == target:
            mac = normalise_mac(st.mac)
            candidates.append({
                "mac": mac,
                "power_dbm": st.power,
                "presence": presence_hint(st.power),
            })
            assoc_macs.discard(mac)
    # Any AP-listed client we did not see a station row for (no power info).
    for mac in sorted(assoc_macs):
        candidates.append({
            "mac": mac, "power_dbm": -100,
            "presence": presence_hint(-100),
        })

    # Prefer the safest-to-clone first: weakest/offline at the top.
    candidates.sort(key=lambda c: c["power_dbm"])

    return {
        "target_bssid": target,
        "target_essid": (ap.essid if ap else ""),
        "target_found": ap is not None,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def print_text(result: dict) -> None:
    print("=" * 62)
    print(" Airsniffer - MAC ACL bypass: candidate allowed MACs")
    print("=" * 62)
    name = result["target_essid"] or "<unknown>"
    print(" Target: %s (%s)" % (name, result["target_bssid"]))
    if not result["target_found"]:
        print(" [!] BSSID not found in this scan - candidates come from station")
        print("     rows only (association to that BSSID).")
    if not result["candidates"]:
        print("-" * 62)
        print(" No associated clients observed for this target.")
        print(" MAC-filter bypass needs at least one allowed (connected) client")
        print(" to impersonate. Capture longer, or the AP may have no clients.")
        print("-" * 62)
        return
    print("-" * 62)
    print(" Candidate MACs to spoof (safest-to-clone first):")
    for i, c in enumerate(result["candidates"], 1):
        print("  %2d. %s   %4d dBm   %s"
              % (i, c["mac"], c["power_dbm"], c["presence"]))
    print("-" * 62)
    print(" Pick one that looks offline, then spoof the adapter to it from the")
    print(" plugin menu. Impersonating an ONLINE client can cause a conflict.")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="List candidate allowed client MACs to bypass a MAC filter "
                    "on a target AP, from a passive airodump-ng CSV.")
    p.add_argument("csv", nargs="?", default="-",
                   help="airodump-ng CSV file (default: stdin)")
    p.add_argument("--bssid", required=True, help="target AP BSSID")
    p.add_argument("--json", action="store_true", help="emit JSON")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.csv == "-":
            text = sys.stdin.read()
        else:
            with open(args.csv, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError as exc:
        print("[!] could not read CSV: %s" % exc, file=sys.stderr)
        return 2

    result = find_candidates(text, args.bssid)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_text(result)
    # Non-zero only on a hard error; "no candidates" is a valid, reported state.
    return 0


if __name__ == "__main__":
    sys.exit(main())
