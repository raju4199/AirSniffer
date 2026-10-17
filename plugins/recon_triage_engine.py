#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Airsniffer - Recon & Target Triage engine
==========================================

Turns a *passive* ``airodump-ng`` scan into a red-team target-prioritisation
report. This is the first, zero-transmission stage of a Wi-Fi engagement: it
reads what was observed over the air and tells the operator which targets are
worth attacking, from which angle, and which Airsniffer module runs that angle.

Input is a standard airodump-ng CSV (``airodump-ng ... -w scan --output-format
csv``), which has two sections: access points, then stations (clients). The
engine only reports what the CSV actually contains - it never invents a client,
a vendor or a PMF state it did not observe. Facts that genuinely cannot be read
from a CSV (PMF/MFP, WPS, Beacon Protection) are flagged as "needs live check",
not guessed.

AUTHORIZED USE ONLY. Run this only against scans of networks you own or are
explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class AP:
    bssid: str
    channel: str
    privacy: str          # raw airodump "Privacy" field, e.g. "WPA2 WPA3"
    cipher: str
    auth: str
    power: int
    essid: str
    clients: list[str] = field(default_factory=list)

    # Derived security posture.
    enc: str = "unknown"          # OPEN / WEP / WPA / WPA2 / WPA3 / WPA2/3
    transition: bool = False      # WPA2+WPA3 mixed (SAE transition) mode
    hidden: bool = False

    def client_count(self) -> int:
        return len(self.clients)


@dataclass
class Station:
    mac: str
    power: int
    bssid: str                    # associated AP, or "(not associated)"
    probes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# airodump-ng CSV parsing
# --------------------------------------------------------------------------- #

AP_HEADER_HINT = "BSSID"
STA_HEADER_HINT = "Station MAC"


def _split_sections(text: str) -> tuple[list[str], list[str]]:
    """Split an airodump CSV into (ap_lines, station_lines) including each
    section's own header row. airodump separates them with a blank line."""
    ap_lines: list[str] = []
    sta_lines: list[str] = []
    bucket: Optional[list[str]] = None
    for raw in text.splitlines():
        line = raw.strip("\r")
        stripped = line.strip()
        if stripped.startswith(AP_HEADER_HINT):
            bucket = ap_lines
            bucket.append(line)
            continue
        if stripped.startswith(STA_HEADER_HINT):
            bucket = sta_lines
            bucket.append(line)
            continue
        if not stripped:
            # Skip blank lines without ending the section. Sections are switched
            # only when a header row is seen, so a stray blank line inside a
            # section does not drop the rows that follow it.
            continue
        if bucket is not None:
            bucket.append(line)
    return ap_lines, sta_lines


def _to_int(value: str, default: int = -100) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default


def _classify(privacy: str, auth: str) -> tuple[str, bool]:
    """Map airodump Privacy/Authentication to a normalised encryption label and
    a transition-mode flag. Returns (enc, transition)."""
    p = (privacy or "").upper()
    has2 = "WPA2" in p
    has3 = "WPA3" in p
    if has2 and has3:
        return "WPA2/3", True
    if has3:
        return "WPA3", False
    if has2:
        return "WPA2", False
    if "WPA" in p:
        return "WPA", False
    if "WEP" in p:
        return "WEP", False
    if p in ("", "OPN") or "OPN" in p:
        return "OPEN", False
    return p.strip() or "unknown", False


def parse_csv(text: str) -> tuple[dict[str, AP], list[Station]]:
    ap_lines, sta_lines = _split_sections(text)

    aps: dict[str, AP] = {}
    if ap_lines:
        reader = csv.reader(ap_lines)
        header = next(reader, None)
        for row in reader:
            if len(row) < 14:
                continue
            bssid = row[0].strip()
            if not bssid:
                continue
            privacy = row[5].strip()
            auth = row[7].strip()
            essid = row[13].strip()
            enc, transition = _classify(privacy, auth)
            ap = AP(
                bssid=bssid,
                channel=row[3].strip(),
                privacy=privacy,
                cipher=row[6].strip(),
                auth=auth,
                power=_to_int(row[8]),
                essid=essid,
                enc=enc,
                transition=transition,
                hidden=(essid == "" or essid.startswith("\x00")),
            )
            aps[bssid] = ap

    stations: list[Station] = []
    if sta_lines:
        reader = csv.reader(sta_lines)
        header = next(reader, None)
        for row in reader:
            if len(row) < 6:
                continue
            mac = row[0].strip()
            if not mac:
                continue
            assoc = row[5].strip()
            probes = [p.strip() for p in row[6:] if p.strip()] if len(row) > 6 else []
            st = Station(mac=mac, power=_to_int(row[3]), bssid=assoc, probes=probes)
            stations.append(st)
            if assoc in aps and assoc not in ("", "(not associated)"):
                aps[assoc].clients.append(mac)

    return aps, stations


# --------------------------------------------------------------------------- #
# Triage scoring + attack-path mapping (the red-team logic)
# --------------------------------------------------------------------------- #

# Each recommendation names a kill-chain stage and the Airsniffer module that
# runs it, so the report is directly actionable.
def recommend(ap: AP) -> list[str]:
    recs: list[str] = []
    has_clients = ap.client_count() > 0

    if ap.enc == "OPEN":
        recs.append("Evil Twin / captive portal (open net, no auth) "
                    "-> Evil Twin menu")
    if ap.enc == "WEP":
        recs.append("WEP crack (legacy, fast) -> WEP attacks menu")
    if ap.enc in ("WPA", "WPA2"):
        if has_clients:
            recs.append("Capture 4-way handshake + offline dictionary "
                        "-> Handshake/PMKID + aircrack/hashcat")
        else:
            recs.append("PMKID capture (clientless) -> Handshake/PMKID tools")
        recs.append("Evil Twin + captive portal (if dict fails) -> Evil Twin menu")
    if ap.transition:
        recs.append("WPA2/3 TRANSITION: downgrade a WPA2 client to capture a "
                    "crackable handshake -> weakest-client path")
        recs.append("Evil Twin + brand-matched captive portal -> Evil Twin menu")
    if ap.enc == "WPA3" and not ap.transition:
        recs.append("WPA3-only: no offline crack. Portal credential capture + "
                    "SAE/protocol attacks -> Modern attacks / Fuzzing DoS")
    # WPS / PMF / Beacon Protection cannot be read from a CSV.
    recs.append("Confirm live: PMF/MFP state, WPS on/off, Beacon Protection "
                "(decides if deauth-to-reconnect is viable)")
    return recs


def score(ap: AP) -> int:
    """Higher = more attractive / lower-effort target for triage ordering."""
    s = 0
    enc_weight = {"OPEN": 50, "WEP": 60, "WPA": 40, "WPA2": 35,
                  "WPA2/3": 30, "WPA3": 15}
    s += enc_weight.get(ap.enc, 20)
    if ap.client_count() > 0:
        s += 25                     # handshake-capturable right now
        s += min(ap.client_count(), 5) * 2
    if ap.transition:
        s += 15                     # downgrade path available
    # Signal: airodump power is negative dBm; closer to 0 is stronger.
    if ap.power > -60:
        s += 15
    elif ap.power > -75:
        s += 8
    return s


def weakest_clients(aps: dict[str, AP]) -> list[tuple[str, str]]:
    """Clients associated to a transition-mode AP - each is a potential WPA2
    downgrade target that makes the whole network crackable."""
    out: list[tuple[str, str]] = []
    for ap in aps.values():
        if ap.transition:
            for mac in ap.clients:
                out.append((mac, ap.essid or ap.bssid))
    return out


def evil_twin_opportunities(stations: list[Station]) -> dict[str, list[str]]:
    """Probed-for SSIDs (preferred-network-list leakage). A client probing for
    an open/known SSID can be lured onto a Karma/evil-twin AP of that name."""
    out: dict[str, list[str]] = {}
    for st in stations:
        for ssid in st.probes:
            out.setdefault(ssid, []).append(st.mac)
    return out


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def build_report(aps: dict[str, AP], stations: list[Station]) -> dict:
    ranked = sorted(aps.values(), key=score, reverse=True)
    return {
        "summary": {
            "access_points": len(aps),
            "stations": len(stations),
            "open": sum(1 for a in aps.values() if a.enc == "OPEN"),
            "wep": sum(1 for a in aps.values() if a.enc == "WEP"),
            "transition": sum(1 for a in aps.values() if a.transition),
            "with_clients": sum(1 for a in aps.values() if a.client_count()),
        },
        "targets": [
            {
                "rank": i + 1,
                "score": score(a),
                "essid": a.essid or ("<hidden>" if a.hidden else ""),
                "bssid": a.bssid,
                "channel": a.channel,
                "enc": a.enc,
                "transition": a.transition,
                "power_dbm": a.power,
                "clients": a.client_count(),
                "attack_path": recommend(a),
            }
            for i, a in enumerate(ranked)
        ],
        "weakest_clients": [
            {"client": mac, "network": net} for mac, net in weakest_clients(aps)
        ],
        "evil_twin_opportunities": [
            {"ssid": ssid, "probing_clients": macs}
            for ssid, macs in evil_twin_opportunities(stations).items()
        ],
    }


def print_text(report: dict) -> None:
    s = report["summary"]
    print("=" * 66)
    print(" Airsniffer - Recon & Target Triage (passive, red-team)")
    print("=" * 66)
    print(" APs: %d | clients: %d | open: %d | WEP: %d | transition: %d | "
          "with-clients: %d"
          % (s["access_points"], s["stations"], s["open"], s["wep"],
             s["transition"], s["with_clients"]))
    print("-" * 66)
    print(" Prioritised targets (highest-value first):")
    for t in report["targets"]:
        name = t["essid"] or "<no-essid>"
        flags = []
        if t["transition"]:
            flags.append("TRANSITION")
        if t["clients"]:
            flags.append("%d client(s)" % t["clients"])
        flag_str = ("  [" + ", ".join(flags) + "]") if flags else ""
        print()
        print("  #%d  score=%d  %s  (%s)" % (t["rank"], t["score"], name, t["bssid"]))
        print("      ch %s | %s | %d dBm%s"
              % (t["channel"], t["enc"], t["power_dbm"], flag_str))
        for r in t["attack_path"]:
            print("       - " + r)

    if report["weakest_clients"]:
        print("-" * 66)
        print(" Weakest clients (downgrade path on transition networks):")
        for w in report["weakest_clients"]:
            print("   %s  on  %s" % (w["client"], w["network"]))

    if report["evil_twin_opportunities"]:
        print("-" * 66)
        print(" Evil-twin / Karma opportunities (probed SSIDs = PNL leakage):")
        for o in report["evil_twin_opportunities"]:
            print("   \"%s\"  <- %d client(s)"
                  % (o["ssid"], len(o["probing_clients"])))
    print("-" * 66)
    print(" Note: PMF/MFP, WPS and Beacon Protection are NOT in airodump CSV -")
    print(" confirm them live before any deauth-based step.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Airsniffer Recon & Target Triage - prioritise a passive "
                    "airodump-ng scan for red-team engagement.")
    p.add_argument("csv", nargs="?", default="-",
                   help="airodump-ng CSV file (default: stdin)")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON instead of the text report")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.csv == "-":
            text = sys.stdin.read()
        else:
            with io.open(args.csv, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError as exc:
        print("[!] could not read CSV: %s" % exc, file=sys.stderr)
        return 2

    aps, stations = parse_csv(text)
    if not aps and not stations:
        print("[!] no access points or stations parsed - is this an "
              "airodump-ng CSV?", file=sys.stderr)
        return 1

    report = build_report(aps, stations)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
