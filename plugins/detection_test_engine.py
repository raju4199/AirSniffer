#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Airsniffer - Detection-perspective test engine
===============================================

Stage 7 of the red-team Wi-Fi methodology: "close the loop". A credible report
does not only say *what* was possible, it says whether the activity was
*detectable*. This engine runs the active detection probes that measure a
target environment's defensive posture (rogue-AP / evil-twin detection, WIDS /
WIPS containment response) and the passive checks that decide whether the
offensive stages are even viable (PMF enforcement, client auto-join hygiene).

Probes:

  * rogue-ap   - stand up a controlled, uniquely-tagged test beacon (an
                 evil-twin "canary") and listen for a WIDS/WIPS reaction:
                 containment deauth/disassoc aimed at the canary BSSID. Reports
                 whether it was contained and how fast. (Active, RoE-gated.)
  * deauth     - emit a small, counted deauth burst against the test canary and
                 watch for a WIPS containment/response signature. Measures
                 whether disruptive activity is detected and answered. (Active,
                 RoE-gated.)
  * pmf-check  - passive. From a beacon's RSN Capabilities field, report the
                 PMF (802.11w / MFP) enforcement state: Disabled / Capable /
                 Required. This decides whether deauth-to-reconnect is viable
                 (ties back to Stage 5) and is a core remediation fact.
  * autojoin   - passive. From probed-SSID (PNL) leakage in an airodump CSV,
                 flag clients that would silently auto-join an open or
                 evil-twin network - a client-side misconfiguration finding.

Two execution modes, exactly like the other Airsniffer engines:

  * simulate (default, safe) - describes the probe and LOGS the test plan,
    transmits nothing, listens to nothing, and NEVER reports a detection it did
    not observe. Observations are explicitly marked "not observed (simulate)".
    Needs no hardware / root / scapy. Good for demos and CI.
  * live - real scapy transmit + sniff on a monitor-mode interface
    (Linux + root). Reports only what was actually observed on the air.

AUTHORIZED USE ONLY. Live mode transmits frames and can trigger a defensive
response - run it only against networks you own or are explicitly authorized to
test. The engine never fabricates observations.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
import time
from typing import Optional

# Probes that put frames on the air (RoE-gated); the rest are passive analysis.
ACTIVE_PROBES = {"rogue-ap", "deauth"}
PROBES = ("rogue-ap", "deauth", "pmf-check", "autojoin")

# 802.11 RSN Capabilities bits that encode Management Frame Protection.
RSN_MFPR_BIT = 6  # Management Frame Protection Required
RSN_MFPC_BIT = 7  # Management Frame Protection Capable


def rand_mac(local: bool = True) -> str:
    """A random MAC; locally-administered + unicast when local=True (canary)."""
    first = random.getrandbits(8)
    if local:
        first = (first & 0xFC) | 0x02  # LAA bit set, unicast
    return "%02X:%s" % (first, ":".join("%02X" % random.getrandbits(8)
                                        for _ in range(5)))


def log_event(cfg: dict, event: dict) -> None:
    with open(os.path.join(cfg["logdir"], "detection_test.jsonl"), "a",
              encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


class Radio:
    """Thin transmit+sniff wrapper. scapy is loaded only in live mode."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.sent = 0
        self.scapy = None
        if cfg["mode"] == "live":
            self._load_scapy()

    def _load_scapy(self):
        try:
            from scapy.all import RadioTap, Dot11  # noqa: F401
            self.scapy = sys.modules["scapy.all"]
        except Exception as exc:  # pragma: no cover - host dependent
            sys.exit("[!] live mode needs scapy (pip install scapy) and Linux "
                     "monitor mode. Import failed: %s" % exc)

    def send_beacon(self, bssid: str, ssid: str) -> Optional[dict]:
        """Transmit (or log) one beacon advertising the canary AP."""
        self.sent += 1
        rec = {"frame": "beacon", "bssid": bssid, "ssid": ssid}
        if self.scapy is None:
            return rec
        S = self.scapy
        dot11 = S.Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                        addr2=bssid, addr3=bssid)
        frame = (S.RadioTap() / dot11 / S.Dot11Beacon(cap="ESS")
                 / S.Dot11Elt(ID=0, info=ssid.encode()))
        S.sendp(frame, iface=self.cfg["iface"], count=1, verbose=0)
        return None

    def send_deauth(self, dst: str, src: str, bssid: str,
                    reason: int = 7) -> Optional[dict]:
        """Transmit (or log) one deauth frame."""
        self.sent += 1
        rec = {"frame": "deauth", "dst": dst, "src": src, "bssid": bssid,
               "reason": reason}
        if self.scapy is None:
            return rec
        S = self.scapy
        dot11 = S.Dot11(addr1=dst, addr2=src, addr3=bssid)
        frame = S.RadioTap() / dot11 / S.Dot11Deauth(reason=reason)
        S.sendp(frame, iface=self.cfg["iface"], count=1, verbose=0)
        return None

    def listen_for_containment(self, canary_bssid: str,
                               seconds: float) -> Optional[dict]:
        """Sniff for a WIDS/WIPS reaction aimed at the canary: deauth/disassoc
        naming the canary BSSID. Returns the first observed hit, or None.

        In simulate mode there is no radio, so this returns None and the caller
        reports 'not observed (simulate)' - it never invents a detection."""
        if self.scapy is None:
            return None
        S = self.scapy
        hit = {}

        def _cb(pkt):
            if not pkt.haslayer(S.Dot11):
                return
            d = pkt.getlayer(S.Dot11)
            is_react = pkt.haslayer(S.Dot11Deauth) or pkt.haslayer(S.Dot11Disas)
            if not is_react:
                return
            addrs = {str(getattr(d, a, "") or "").lower()
                     for a in ("addr1", "addr2", "addr3")}
            if canary_bssid.lower() in addrs:
                hit["ts"] = time.time()
                hit["src"] = str(getattr(d, "addr2", ""))
                hit["dst"] = str(getattr(d, "addr1", ""))
                hit["type"] = ("deauth" if pkt.haslayer(S.Dot11Deauth)
                               else "disassoc")

        t0 = time.time()
        S.sniff(iface=self.cfg["iface"], timeout=seconds,
                stop_filter=lambda _p: bool(hit), prn=_cb)
        if hit:
            hit["latency_s"] = round(hit["ts"] - t0, 3)
            return hit
        return None


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #

def probe_rogue_ap(cfg: dict, radio: Radio) -> dict:
    """Beacon a uniquely-tagged evil-twin canary and listen for containment."""
    canary_ssid = cfg["ssid"]
    canary_bssid = cfg["canary_mac"]
    for _ in range(cfg["count"]):
        radio.send_beacon(canary_bssid, canary_ssid)
    observed = radio.listen_for_containment(canary_bssid, cfg["listen"])
    detected = observed is not None
    result = {
        "probe": "rogue-ap", "canary_bssid": canary_bssid,
        "canary_ssid": canary_ssid, "beacons_sent": radio.sent,
        "wids_detected": detected if cfg["mode"] == "live" else None,
        "observation": observed if cfg["mode"] == "live"
        else "not observed (simulate)",
    }
    if cfg["mode"] == "live":
        print("[+] rogue-ap: %d beacons as %s (%s); containment %s"
              % (radio.sent, canary_ssid, canary_bssid,
                 ("DETECTED in %ss" % observed["latency_s"]) if detected
                 else "not observed in %ss" % cfg["listen"]))
    else:
        print("[+] rogue-ap: would beacon %d frames as canary %s (%s) and "
              "listen %ss for WIDS containment"
              % (cfg["count"], canary_ssid, canary_bssid, cfg["listen"]))
    return result


def probe_deauth(cfg: dict, radio: Radio) -> dict:
    """Emit a counted deauth burst at the canary and watch for a WIPS answer."""
    ap, sta = cfg["ap_mac"], cfg["sta_mac"]
    for _ in range(cfg["count"]):
        radio.send_deauth(dst=sta, src=ap, bssid=ap)
    observed = radio.listen_for_containment(ap, cfg["listen"])
    detected = observed is not None
    result = {
        "probe": "deauth", "ap_mac": ap, "sta_mac": sta,
        "frames_sent": radio.sent,
        "wips_detected": detected if cfg["mode"] == "live" else None,
        "observation": observed if cfg["mode"] == "live"
        else "not observed (simulate)",
    }
    if cfg["mode"] == "live":
        print("[+] deauth: %d frames at %s; WIPS response %s"
              % (radio.sent, ap,
                 ("DETECTED in %ss" % observed["latency_s"]) if detected
                 else "not observed in %ss" % cfg["listen"]))
    else:
        print("[+] deauth: would send %d deauth frames at %s and listen %ss "
              "for a WIPS containment response"
              % (cfg["count"], ap, cfg["listen"]))
    return result


def classify_pmf(rsn_caps: int) -> dict:
    """Decode PMF state from a 16-bit RSN Capabilities value."""
    mfpc = (rsn_caps >> RSN_MFPC_BIT) & 1
    mfpr = (rsn_caps >> RSN_MFPR_BIT) & 1
    if not mfpc:
        state, deauth = "disabled", "deauth works (no PMF)"
    elif mfpc and not mfpr:
        state, deauth = "capable (optional)", "deauth works on non-PMF clients"
    else:
        state, deauth = "required", "classic deauth blocked (use PMF-bypass DoS)"
    return {"mfpc": mfpc, "mfpr": mfpr, "pmf_state": state,
            "deauth_viability": deauth}


def probe_pmf_check(cfg: dict, radio: Radio) -> dict:
    """Passive: report PMF enforcement from the AP's RSN Capabilities."""
    caps = cfg["rsn_caps"]
    if caps is None:
        result = {"probe": "pmf-check", "pmf_state": "unknown",
                  "note": "no --rsn-caps supplied; confirm live from a beacon "
                          "(RSN Capabilities field) - never guess"}
        print("[i] pmf-check: no RSN Capabilities provided - cannot determine "
              "PMF state. Capture a beacon and pass --rsn-caps 0xNNNN.")
        return result
    info = classify_pmf(caps)
    result = {"probe": "pmf-check", "rsn_caps": "0x%04x" % caps}
    result.update(info)
    print("[+] pmf-check: RSN caps 0x%04x -> PMF %s (MFPC=%d MFPR=%d); %s"
          % (caps, info["pmf_state"], info["mfpc"], info["mfpr"],
             info["deauth_viability"]))
    return result


def probe_autojoin(cfg: dict, radio: Radio) -> dict:
    """Passive: flag clients leaking a PNL (probed SSIDs) -> auto-join risk."""
    leakers = []
    path = cfg["csv"]
    if path and os.path.isfile(path):
        leakers = _parse_probe_leakage(path)
    result = {"probe": "autojoin", "csv": path or None,
              "leaking_clients": leakers, "count": len(leakers)}
    if path:
        print("[+] autojoin: %d client(s) leaking a preferred-network list "
              "(auto-join / evil-twin risk)" % len(leakers))
        for lk in leakers:
            print("      %s probes: %s" % (lk["station"],
                                           ", ".join(lk["probed"])))
    else:
        print("[i] autojoin: no --csv supplied. Feed an airodump CSV with a "
              "station/'Probed ESSIDs' section to flag auto-join leakage.")
    return result


def _parse_probe_leakage(path: str) -> list:
    """Pull (station, [probed SSIDs]) rows from an airodump-ng CSV."""
    leakers = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        rows = list(csv.reader(fh))
    in_sta = False
    for row in rows:
        cells = [c.strip() for c in row]
        if not any(cells):
            continue
        if cells[0] == "Station MAC":
            in_sta = True
            continue
        if cells[0] == "BSSID":
            in_sta = False
            continue
        if in_sta and len(cells) >= 7:
            probed = [p.strip() for p in cells[6:] if p.strip()]
            if probed:
                leakers.append({"station": cells[0], "probed": probed})
    return leakers


DISPATCH = {
    "rogue-ap": probe_rogue_ap,
    "deauth": probe_deauth,
    "pmf-check": probe_pmf_check,
    "autojoin": probe_autojoin,
}


def run(cfg: dict, radio: Radio) -> dict:
    result = DISPATCH[cfg["probe"]](cfg, radio)
    result["ts"] = time.time()
    result["mode"] = cfg["mode"]
    result["active"] = cfg["probe"] in ACTIVE_PROBES
    log_event(cfg, result)
    return result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _parse_caps(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def parse_args(argv: list) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Airsniffer detection-perspective test engine (Stage 7).")
    p.add_argument("--probe", required=True, choices=PROBES)
    p.add_argument("--mode", default="simulate", choices=["simulate", "live"])
    p.add_argument("--iface", default="wlan0mon")
    p.add_argument("--ap-mac", default="AA:AA:AA:AA:AA:AA")
    p.add_argument("--sta-mac", default="BB:BB:BB:BB:BB:BB")
    p.add_argument("--canary-mac", default=None,
                   help="BSSID for the rogue-ap canary (random LAA if unset)")
    p.add_argument("--ssid", default="TARGET_SSID")
    p.add_argument("--channel", default="1")
    p.add_argument("--count", type=int, default=32,
                   help="beacons/frames to send before listening")
    p.add_argument("--listen", type=float, default=15.0,
                   help="seconds to sniff for a defensive reaction (live)")
    p.add_argument("--rsn-caps", default=None,
                   help="RSN Capabilities for pmf-check, e.g. 0x00c0")
    p.add_argument("--csv", default=None,
                   help="airodump CSV for the autojoin probe")
    p.add_argument("--logdir", default=".")
    p.add_argument("--seed", type=int, default=None)
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.seed is not None:
        random.seed(args.seed)
    os.makedirs(args.logdir, exist_ok=True)

    cfg = {
        "probe": args.probe, "mode": args.mode, "iface": args.iface,
        "ap_mac": args.ap_mac, "sta_mac": args.sta_mac,
        "canary_mac": args.canary_mac or rand_mac(),
        "ssid": args.ssid, "channel": args.channel, "count": args.count,
        "listen": args.listen, "rsn_caps": _parse_caps(args.rsn_caps),
        "csv": args.csv, "logdir": args.logdir,
    }

    banner = ("SIMULATION (no frames transmitted, nothing observed)"
              if args.mode == "simulate" else "LIVE (transmit + sniff)")
    kind = "active" if args.probe in ACTIVE_PROBES else "passive"
    print("=" * 62)
    print(" Airsniffer detection test - %s" % banner)
    print(" probe %s (%s) | iface %s | ch %s"
          % (args.probe, kind, cfg["iface"], cfg["channel"]))
    print("=" * 62)

    radio = Radio(cfg)
    run(cfg, radio)

    print("-" * 62)
    if args.mode == "simulate":
        print("[i] simulation only - nothing transmitted and no detection "
              "claimed. Run --mode live (Linux + root + monitor mode) to "
              "measure the real defensive response.")
    print("[=] done. log: %s"
          % os.path.join(cfg["logdir"], "detection_test.jsonl"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
