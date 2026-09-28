<div align="center">

# Airsniffer

![Banner](imgs/banners/airsniffer_banner.png)

**A powerful, all-in-one wireless security auditing framework for Linux.**

[![Version-shield]](CHANGELOG.md)
[![Bash-shield]](http://tldp.org/LDP/abs/html/bashver4.html#AEN21220)
[![License-shield]](LICENSE)
[![Platform-shield]](#requirements)
[![Auth-shield]](#legal-disclaimer)

*Discover · Audit · Report — from a single, menu-driven console.*

<br>

![WPA2 capture-and-crack workflow](imgs/banners/airsniffer_workflow.gif)

*The core workflow: deauth a client, capture the WPA2 four-way handshake, then crack it offline.*

<br>

![Evil Twin with a vendor-matched captive portal](imgs/banners/airsniffer_evil_twin.gif)

*Evil Twin: fingerprint the AP's OUI to serve a vendor-matched portal, herd the client over with a dedicated deauth radio, and verify every submitted PSK against the captured handshake.*

</div>

---

## Overview

**Airsniffer** is a modular Bash toolkit that unifies the entire Wi-Fi audit workflow into
one guided, terminal-based interface. Instead of memorising a dozen separate command-line
tools and their flags, you drive the whole engagement — interface setup, discovery,
handshake capture, offline cracking, and rogue-AP assessment — from a clean, interactive
menu with sane defaults and safety checks at every step.

It is built for **authorized penetration testers, red teams, CTF players, students, and
researchers** who need repeatable results without the boilerplate.

---

## Highlights

- **Guided console** — auto-detects your environment, dependencies, and adapters; walks you
  through monitor-mode setup and channel selection.
- **Full attack surface coverage** — WEP, WPA/WPA2 and WPA3 (SAE) auditing, PMKID capture,
  handshake capture, and WPS assessment (Pixie-Dust, bruteforce, known-PIN database).
- **Evil Twin suite with vendor-aware captive portals** — the rogue AP fingerprints the
  target gateway by its OUI and renders a matching, professional portal template
  automatically (see below).
- **Dedicated dual-adapter deauth** — when a second Wi-Fi adapter is present, the Evil Twin
  flow automatically runs the deauth from that adapter (and follows the target across
  channels), keeping the captive-portal AP stable (see below).
- **WPA3 / PMF awareness** — before a deauth-based attack, Airsniffer warns you when the
  target enforces Protected Management Frames (802.11w), so you don't waste time on
  techniques modern networks ignore (see below).
- **Offline cracking** — dictionary, bruteforce and rule-based attacks with `aircrack-ng`
  and `hashcat` (GPU-accelerated) integration.
- **DoS toolkit** — deauthentication, Auth DoS, beacon flood, WDS confusion and more for
  controlled resilience testing.
- **Extensible plugin system** — drop-in hooks let you extend or override behaviour without
  patching the core script.
- **Multi-language interface** — localised menus with an English fallback for new strings.

---

## What's New in This Fork

Airsniffer builds on airgeddon with a refreshed interface and several practical upgrades to
make engagements more effective against modern (2025+) networks.

### Vendor-aware Evil Twin templates

When the *advanced captive portal* mode is enabled, Airsniffer reads the target access
point's MAC OUI, identifies the hardware vendor, and serves a portal styled to match that
device class — so the page a client sees looks like the login screen they expect from their
own gateway.

| Detected vendor family | Template | Look & feel |
|---|---|---|
| Cisco, Aruba, Juniper, Fortinet, Ubiquiti, Arista | `enterprise` | Squared corners, accent bar, uppercase "Secure Network Access" branding |
| Arris, Technicolor, Huawei, ZTE, FRITZ!Box, Motorola, … | `isp` | Gradient broadband-gateway card, pill buttons |
| Netgear, Asus, Linksys, Belkin, Zyxel, Mercusys, … | `consumer` | Soft-shadowed "Wi-Fi Router Login" card |
| Anything unrecognised | `modern` | Polished Airsniffer default theme |

The vendor's real brand colours and logo (shipped with the tool) drive the theme, while the
credential-validation flow — live verification against the captured handshake — is unchanged.

### Automatic dedicated deauth adapter

Running the deauth on the same radio as the rogue AP destabilises the captive portal. When a
**second Wi-Fi adapter** is connected, Airsniffer now **defaults DoS pursuit mode to on** in
the Evil Twin flow and auto-selects the free adapter for the deauth — so one radio serves the
AP + portal while the other handles the deauth and even follows the target if it changes
channel. With a single adapter, behaviour is unchanged.

### WPA3 / PMF effectiveness warning

WPA3 enforces Protected Management Frames (802.11w), which makes clients ignore
deauthentication frames. Before a deauth-based DoS or Evil Twin herding attack, Airsniffer now
detects a WPA3 target and **warns that the deauth will likely have no effect**, pointing you
to PMF-resilient alternatives (the WPA3/SAE menu, an Auth DoS, or capturing new associations
instead of forcing existing clients off). This saves time and avoids false "target is secure"
conclusions.

### Refreshed interface

New animated intro (ANSI wordmark + mascot), consistent branded menu headers across every
screen, and professional, de-branded wording throughout.

---

## Requirements

- A Linux distribution (Kali, Parrot, BlackArch, Arch, Debian/Ubuntu, etc.)
- **Bash 4.2+**
- **Root privileges**
- A wireless adapter that supports **monitor mode** (and packet injection for active tests)
- Core tools: the `aircrack-ng` suite, plus optional `hashcat`, `hostapd`, `dnsmasq`,
  `lighttpd`, `bettercap`, `reaver`/`bully`, and others — Airsniffer checks for these on
  startup and tells you what's missing.

---

## Quick Start

```bash
git clone https://github.com/raju4199/AirSniffer.git
cd AirSniffer
sudo bash airsniffer.sh
```

On first launch the tool runs a dependency check and offers to help resolve anything that
is missing, then drops you into the main menu.

### Docker

A `Dockerfile` is included for a containerised run:

```bash
docker build -t airsniffer .
docker run --rm -it --privileged --net=host airsniffer
```

---

## Configuration

Airsniffer reads optional defaults from an `.airsnifferrc` file (interface names, preferred
paths, colour and language preferences, and more), so you can preseed your setup and skip
repetitive prompts. See the sample [.airsnifferrc](.airsnifferrc) in this repository.

---

## Plugins

The plugin system lets you extend the framework cleanly. Start from
[plugins/plugin_template.sh](plugins/plugin_template.sh) — define the hooks you want and
drop the file into `plugins/`; Airsniffer loads it automatically.

---

## Legal Disclaimer

> **Airsniffer is intended strictly for legal, authorized security testing and education.**
>
> Use it only on networks you own or for which you have **explicit, written permission** to
> test. Intercepting traffic, capturing credentials, or disrupting networks you are not
> authorized to assess is illegal in most jurisdictions. You are solely responsible for your
> actions. The authors and contributors accept **no liability** for misuse or for any damage
> caused by this software.

---

## License & Credits

Airsniffer is released under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).

Airsniffer is a fork of, and builds upon the excellent work of, the
[**airgeddon**](https://github.com/v1s1t0r1sh3r3/airgeddon) project and its community. Huge
thanks to the original authors and to everyone maintaining the wider wireless-auditing
tooling ecosystem (the Aircrack-ng, hashcat, hostapd and reaver teams, among many others).

---

<div align="center">

*Built for defenders. Use responsibly.*

</div>

[Banner]: imgs/banners/airsniffer_banner.png
[Version-shield]: https://img.shields.io/badge/version-12.02-0093ee.svg?style=flat-square&colorA=273133 "Version"
[Bash-shield]: https://img.shields.io/badge/bash-4.2%2B-00db00.svg?style=flat-square&colorA=273133 "Bash 4.2 or later"
[License-shield]: https://img.shields.io/badge/license-GPL%20v3%2B-bd0000.svg?style=flat-square&colorA=273133 "GPL v3+"
[Platform-shield]: https://img.shields.io/badge/platform-Linux-1793d1.svg?style=flat-square&colorA=273133 "Linux"
[Auth-shield]: https://img.shields.io/badge/use-authorized%20testing%20only-orange.svg?style=flat-square&colorA=273133 "Authorized testing only"
