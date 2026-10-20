# Red-Team Wi-Fi Testing Methodology (Airsniffer SOP)

> **Authorized use only.** Every step below assumes a signed scope and rules of
> engagement (RoE). Passive stages are safe to run anywhere you are permitted to
> listen; every transmitting/disruptive step requires explicit per-target
> authorization and must be confirmed against the in-scope BSSID list first.

This is the operator playbook. It follows a Wi-Fi kill chain and maps each stage
to the Airsniffer module that runs it, so the tool can be measured against a
real engagement flow. It is deliberately "test from every perspective": the
access point, the client, the protocol/implementation, availability, and
detection.

Legend: **[available]** ships today · **[planned]** not yet implemented, do not
assume it works.

---

## Stage 0 — Pre-engagement

- Confirm scope: in-scope SSIDs/BSSIDs, bands (2.4 / 5 / 6 GHz), test window,
  and whether disruptive (deauth/DoS) testing is permitted or passive-only.
- Safety rails: client exclusion list (medical/IoT/unknown third parties), a
  named stop contact, and a bounded blast radius.
- Rig check: a monitor-mode + injection-capable adapter (e.g. RTL8812AU); a
  second adapter if you want capture and deauth on separate radios.
- Deliverable: documented RoE and baseline before a single frame is sent.

## Stage 1 — Passive recon (zero transmission)

Listen only. Build the map before touching anything.

- Enumerate APs, hidden SSIDs, clients, and client probe requests (the
  preferred-network list that leaks from devices).
- Capture to an `airodump-ng` CSV for triage.

**Airsniffer:** core *Explore for targets* / `airodump-ng --output-format csv`.
Then **[available] Recon & Target Triage** (`recon_triage.sh` →
`recon_triage_engine.py`) ingests the CSV and produces:
- per-AP security posture (OPEN/WEP/WPA/WPA2/WPA3, transition mode),
- a **prioritised target list** with a per-target recommended attack path,
- **weakest clients** (WPA2 clients on a transition network = downgrade path),
- **evil-twin / Karma openings** (probed SSIDs = PNL leakage).

> The triage report intentionally flags **PMF/MFP, WPS and Beacon Protection as
> "confirm live"** — these are not present in an airodump CSV and must never be
> guessed. They decide whether deauth-to-reconnect is even viable (see Stage 5).

## Stage 2 — Access-point perspective

- WPA2 / WPA3-transition: capture the **4-way handshake or PMKID**, then offline
  dictionary/`hashcat`.
- **Weakest-client rule:** on a transition network a single WPA2 client makes
  the whole network crackable; identify it from the unencrypted auth-type field
  in handshake message 1.
- WPS enabled: `wash` → Pixie-Dust / `reaver`.
- WPA3-SAE only: no offline crack via handshake, but **Dragonblood** recovers the
  password through SAE timing/cache side-channels when the AP offers MODP or
  Brainpool groups (DragonTime → DragonForce). Else pivot to Stage 3 or 4.
- **MAC filtering (ACL):** a MAC whitelist is a weak access control. The allowed
  MACs are the clients already associated to the AP; impersonate one (ideally
  while it is offline) to be admitted.

**Airsniffer:** core *Handshake/PMKID tools*, *WEP/WPS attacks menu*, aircrack /
hashcat integration; **[available] MAC ACL bypass** (`mac_acl_bypass.sh` +
`mac_acl_engine.py`) lists candidate allowed MACs from a passive scan and spoofs
the adapter to a chosen one (with restore).

## Stage 3 — Client perspective (often the weakest link)

- **Evil twin / Karma / MANA:** answer a client's probed SSIDs and lure it onto
  an attacker AP.
- **Captive portal, brand/vendor-matched:** mimic the target router's page and
  language to raise credential/PSK capture rates. This is Airsniffer's core
  direction (vendor-aware portal templates).
- Enterprise (WPA2/3-Ent): `hostapd-wpe` → `asleap`/`john` on captured
  MSCHAPv2.
- **KRACK, FragAttacks, Kr00k:** these target the *client*, not the AP.

**Airsniffer:** core *Evil Twin* menu (+ vendor-matched captive portal, auto-
selected from the target OUI); **[available] Modern Wi-Fi protocol attacks**
(`modern_wifi_attacks.sh`) for KRACK / FragAttacks / MacStealer / Kr00k
launchers; **[available] Captive portal credential verification**
(`portal_verify.sh` + `portal_verify_engine.py`) - extracts the submitted
password from the portal log or a sniffed plaintext HTTP POST, and for a
WPA3-only target verifies it by a live SAE association (the "active dictionary"
path, since offline is impossible).

## Stage 4 — Protocol / implementation perspective

The surface beyond "deauth doesn't work on WPA3". Attack the stack itself.

- Management / control / **WPA3-SAE fuzzing** → firmware DoS and parsing bugs
  that keep working **despite PMF**.
- SSID Confusion (CVE-2023-52424), MacStealer / Framing Frames (client-isolation
  bypass), downgrade attacks.

**Airsniffer:** **[available] Fuzzing DoS** (`fuzzing_dos.sh` +
`fuzzing_dos_engine.py`, WPAxFuzz-style) with `simulate` (safe) and `live`
modes; the attack module replays confirmed disruptions and writes a standalone
reproduction exploit. The **Modern attacks menu** also carries SAE fuzzing,
SSID-Confusion advisory, a **[available] Dragonblood** launcher (DragonTime →
DragonForce SAE side-channel), and **[available]** OWE / Enhanced Open and DPP /
Wi-Fi Easy Connect advisory modules.

## Stage 5 — Availability / DoS perspective (RoE-gated)

Only if the RoE permits disruption. Each action gated behind explicit target
confirmation.

- Deauth / disassoc (effective when PMF is off).
- **Pre-handshake deauth** — works even with PMF mandatory, by hitting a client
  before the 4-way handshake installs the PTK.
- **SA-Query trigger** — unprotected mgmt frames exploit inconsistent 802.11w
  SA-Query handling (Schepers, Ranganathan, Vanhoef, WiSec 2022).
- **DragonDrain** (SAE Commit flood, ≥16 forged commits/sec) and **Bad-Token**
  DoS against SAE (Vanhoef & Ronen 2019; Lounis & Zulkernine 2019).
- RF jamming is normally out of scope.

**Airsniffer:** core *DoS* menu (classic deauth) with WPA3/PMF warning;
**[available]** Fuzzing DoS (firmware parsing bugs) and **[available] PMF-bypass
DoS** (`pmf_dos.sh` + `pmf_dos_engine.py`) — pre-handshake deauth, SA-Query,
DragonDrain and Bad-Token, all PMF-resistant, with simulate + live modes.

## Stage 6 — Post-exploitation perspective

Network access is the entry point, not the finish line.

- Enumerate the subnet, IoT/cameras, and vulnerable hosts.
- MITM (`bettercap`), DNS spoofing, and lateral movement / pivot.

**Airsniffer:** post-auth tooling / `bettercap` handoff (manual).

## Stage 7 — Detection perspective (close the loop)

A credible red-team report also states whether the activity was *detectable*.

- Test rogue-AP / evil-twin detection and any WIDS/WIPS response.
- Verify PMF enforcement and client auto-join misconfiguration.
- Note which attacks were logged or alerted vs silent.

**Airsniffer:** posture facts surfaced in triage + target analysis panel;
**[available] Detection-perspective testing** (`detection_test.sh` +
`detection_test_engine.py`) runs four probes: **rogue-ap** beacons a uniquely-
tagged evil-twin canary and listens for WIDS/WIPS containment aimed at it;
**deauth** emits a counted burst and watches for a WIPS response; **pmf-check**
(passive) decodes PMF enforcement from the AP's RSN Capabilities (deciding
whether deauth is viable at all, Stage 5); **autojoin** (passive) flags clients
leaking a preferred-network list. Simulate + live modes; the engine never
reports a detection it did not observe.

## Stage 8 — Reporting

For every finding: evidence (pcap/CSV), reproduction steps, impact, and
remediation. Core remediations to recommend:

- PMF **mandatory**; drop WPA2/WPA3 transition mode; WPA3-only where possible.
- Strong PSK (≥ 12 chars, non-guessable); WPS off; unique SSID/credentials.
- Client hygiene: forget open networks, disable auto-join, disable idle radios.

---

## Coverage matrix

| Kill-chain stage | Perspective | Airsniffer module | Status |
|---|---|---|---|
| 1 Passive recon | — | Explore + **Recon & Target Triage** | available |
| 2 AP | access point | Handshake/PMKID, WEP/WPS, aircrack/hashcat, **MAC ACL bypass** | available |
| 3 Client | client | Evil Twin + vendor portal, Modern attacks, **portal cred verify (WPA3)** | available |
| 4 Protocol | implementation | Fuzzing DoS, Modern attacks | available |
| 5 DoS | availability | DoS menu, Fuzzing DoS, **PMF-bypass DoS** | available |
| 6 Post-ex | network | bettercap handoff | manual |
| 7 Detection | defensive | triage posture facts + **Detection-perspective testing** (rogue-ap / deauth / pmf-check / autojoin) | available |

## Design principles this tool holds to

- **Never fabricate observations.** The triage engine reports only what the
  capture contains; facts not in the data are flagged "confirm live".
- **Passive first.** Discovery and triage transmit nothing.
- **Gate disruption.** Live injection and DoS require explicit authorization and
  a confirmed target.
- **No shell-string command injection.** Subprocess calls use argument arrays;
  values such as spaced SSIDs are passed as single arguments.
- **Separate available from planned.** `[planned]` items are not wired up; do
  not report them as working.
