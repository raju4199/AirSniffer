#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### Airsniffer plugin: Detection-perspective testing ######
#
# Stage 7 of the red-team methodology - "close the loop". A credible engagement
# report states whether the activity was *detectable*. This plugin drives
# detection_test_engine.py, which runs the detection probes:
#
#   * rogue-ap  - beacon a uniquely-tagged evil-twin canary and listen for a
#                 WIDS/WIPS containment reaction (deauth aimed at the canary).
#   * deauth    - emit a counted deauth burst and watch for a WIPS response.
#   * pmf-check - passive: decode PMF (802.11w) enforcement from the AP's RSN
#                 Capabilities (decides whether deauth is even viable).
#   * autojoin  - passive: flag clients leaking a preferred-network list
#                 (probed SSIDs) -> silent auto-join / evil-twin risk.
#
# SIMULATION (default) describes the probe, transmits nothing, listens to
# nothing, and never claims a detection it did not observe. LIVE transmits +
# sniffs on a monitor-mode interface and is gated behind an authorization
# prompt. All engine args are passed as an array (spaced SSIDs stay intact).
#
# AUTHORIZED USE ONLY.

###### GENERIC PLUGIN VARS ######

plugin_name="Detection-perspective testing"
plugin_description="Stage 7: measure WIDS/WIPS detection, PMF enforcement and client auto-join hygiene (sim + live)"
plugin_author="Airsniffer"

plugin_enabled=1
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)/airsniffer_ui.sh" 2> /dev/null || true

###### PLUGIN REQUIREMENTS ######

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

###### WPA3 MENU REGISTRATION ######

detection_test_menu_string_id=9160

detection_test_plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
detection_test_engine="${detection_test_plugin_dir}/detection_test_engine.py"

#Session state.
detection_test_mode="simulate"      # simulate | live
detection_test_probe="pmf-check"    # rogue-ap | deauth | pmf-check | autojoin
detection_test_sta_mac=""           # victim client MAC (deauth probe)
detection_test_rsn_caps=""          # RSN Capabilities for pmf-check (0xNNNN)
detection_test_csv=""               # airodump CSV for autojoin
detection_test_count=32
detection_test_listen=15
detection_test_authorized=0

detection_test_register_labels() {
	local lang
	local label="Detection-perspective testing (WIDS/WIPS, PMF enforcement, auto-join) *"
	for lang in ENGLISH SPANISH FRENCH CATALAN PORTUGUESE RUSSIAN GREEK ITALIAN POLISH GERMAN TURKISH ARABIC CHINESE; do
		arr["${lang}",${detection_test_menu_string_id}]="${label}"
	done
}
detection_test_register_labels

plugin_wpa3_menu_option_function="detection_test_menu"
plugin_wpa3_menu_option_language_string="${detection_test_menu_string_id}"

###### HELPERS ######

detection_test_title() {
	as_ui_header "${1}"
}

detection_test_pause() {
	as_ui_pause
}

detection_test_python() {
	if command -v python3 > /dev/null 2>&1; then echo "python3"
	elif command -v python > /dev/null 2>&1; then echo "python"
	else echo ""; fi
}

detection_test_valid_mac() {
	[[ "${1}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

#Probes that put frames on the air (need monitor mode + authorization).
detection_test_is_active() {
	case "${detection_test_probe}" in
		rogue-ap|deauth) return 0 ;;
		*) return 1 ;;
	esac
}

detection_test_authorization_gate() {
	if [ "${detection_test_authorized}" -eq 1 ]; then return 0; fi
	echo
	echo -e "${red_color}LIVE MODE - AUTHORIZED TESTING ONLY${normal_color}"
	echo -e "${yellow_color}Live active probes transmit real frames and can trigger a defensive"
	echo -e "response. Only run them against a network you own or are explicitly"
	echo -e "authorized to test.${normal_color}"
	echo
	read -rp "$(echo -e "${green_color}Do you have authorization for this target? [y/N]: ${normal_color}")" _auth
	case "${_auth}" in
		y|Y|yes|YES) detection_test_authorized=1; return 0 ;;
		*) echo; echo -e "${red_color}Aborted. Authorization is required.${normal_color}"; return 1 ;;
	esac
}

###### SETUP (reuses Airsniffer core) ######

detection_test_select_interface() {
	select_interface
	detection_test_pause
}

detection_test_ensure_monitor() {
	if [ -z "${interface}" ]; then
		echo; echo -e "${red_color}No interface selected.${normal_color} Use option 1 first."; detection_test_pause; return 1
	fi
	if [ "${ifacemode}" = "Monitor" ]; then
		echo; echo -e "${green_color}${interface} already in monitor mode.${normal_color}"; detection_test_pause; return 0
	fi
	echo; echo -e "${yellow_color}Putting ${interface} into monitor mode...${normal_color}"
	monitor_option "${interface}"
	detection_test_pause
}

detection_test_select_target() {
	if [ -z "${interface}" ]; then
		echo; echo -e "${red_color}No interface selected.${normal_color} Use option 1 first."; detection_test_pause; return 1
	fi
	if [ "${ifacemode}" != "Monitor" ]; then
		echo -e "${yellow_color}Enabling monitor mode first...${normal_color}"
		monitor_option "${interface}" || { detection_test_pause; return 1; }
	fi
	explore_for_targets_option "WPA3"
	[ -n "${bssid}" ] && echo -e "${green_color}Target locked:${normal_color} ${essid:-<hidden>} (${bssid}, ch ${channel})"
	detection_test_pause
}

detection_test_set_sta_mac() {
	local mac
	read -rp "$(echo -e "${green_color}Victim client MAC (AA:BB:CC:DD:EE:FF, blank to clear): ${normal_color}")" mac
	if [ -z "${mac}" ]; then
		detection_test_sta_mac=""; echo -e "${yellow_color}Cleared.${normal_color}"
	elif detection_test_valid_mac "${mac}"; then
		detection_test_sta_mac="${mac}"; echo -e "${green_color}Victim STA set:${normal_color} ${detection_test_sta_mac}"
	else
		echo -e "${red_color}Invalid MAC format.${normal_color} Not changed."
	fi
	detection_test_pause
}

detection_test_set_rsn_caps() {
	local caps
	read -rp "$(echo -e "${green_color}RSN Capabilities from a beacon (e.g. 0x00c0, blank to clear): ${normal_color}")" caps
	if [ -z "${caps}" ]; then
		detection_test_rsn_caps=""; echo -e "${yellow_color}Cleared.${normal_color}"
	elif [[ "${caps}" =~ ^(0[xX])?[0-9A-Fa-f]+$ ]]; then
		detection_test_rsn_caps="${caps}"; echo -e "${green_color}RSN caps set:${normal_color} ${detection_test_rsn_caps}"
	else
		echo -e "${red_color}Invalid hex value.${normal_color} Not changed."
	fi
	detection_test_pause
}

detection_test_set_csv() {
	local path
	read -rp "$(echo -e "${green_color}Path to airodump CSV (blank to clear): ${normal_color}")" path
	if [ -z "${path}" ]; then
		detection_test_csv=""; echo -e "${yellow_color}Cleared.${normal_color}"
	elif [ -f "${path}" ]; then
		detection_test_csv="${path}"; echo -e "${green_color}CSV set:${normal_color} ${detection_test_csv}"
	else
		echo -e "${red_color}File not found.${normal_color} Not changed."
	fi
	detection_test_pause
}

###### RUN ######

detection_test_run() {
	local py; py="$(detection_test_python)"
	if [ -z "${py}" ]; then echo -e "${red_color}Python 3 not found.${normal_color}"; detection_test_pause; return; fi
	if [ ! -f "${detection_test_engine}" ]; then echo -e "${red_color}Engine not found:${normal_color} ${detection_test_engine}"; detection_test_pause; return; fi

	local outdir="${tmpdir:-/tmp/}detection_test"
	mkdir -p "${outdir}" 2> /dev/null

	local args=(
		"${detection_test_engine}"
		--probe "${detection_test_probe}"
		--mode "${detection_test_mode}"
		--iface "${interface:-wlan0mon}"
		--ap-mac "${bssid:-AA:AA:AA:AA:AA:AA}"
		--sta-mac "${detection_test_sta_mac:-BB:BB:BB:BB:BB:BB}"
		--ssid "${essid:-TARGET_SSID}"
		--channel "${channel:-1}"
		--count "${detection_test_count}"
		--listen "${detection_test_listen}"
		--logdir "${outdir}"
	)
	[ -n "${detection_test_rsn_caps}" ] && args+=(--rsn-caps "${detection_test_rsn_caps}")
	[ -n "${detection_test_csv}" ] && args+=(--csv "${detection_test_csv}")

	if [ "${detection_test_mode}" = "live" ]; then
		#Only the active probes transmit; passive probes run live without a gate.
		if detection_test_is_active; then
			if [ -z "${bssid}" ]; then
				echo -e "${red_color}No target locked.${normal_color} Use option 3 first."; detection_test_pause; return
			fi
			if ! detection_test_authorization_gate; then detection_test_pause; return; fi
			if [ -z "${interface}" ] || [ "${ifacemode}" != "Monitor" ]; then
				echo -e "${red_color}Live active probes need a monitor-mode interface.${normal_color} Use options 1-2."; detection_test_pause; return
			fi
			echo -e "${yellow_color}Setting ${interface} to channel ${channel}...${normal_color}"
			iw dev "${interface}" set channel "${channel}" > /dev/null 2>&1
		fi
		echo -e "${blue_color}Running LIVE detection probe '${detection_test_probe}'...${normal_color}"
		echo
		"${py}" "${args[@]}"
		echo
		echo -e "${green_color}Detection log:${normal_color} ${outdir}"
	else
		echo -e "${blue_color}Running SIMULATION (nothing transmitted, nothing claimed)...${normal_color}"
		echo
		"${py}" "${args[@]}"
		echo
		echo -e "${green_color}Simulation log:${normal_color} ${outdir}"
	fi
	detection_test_pause
}

###### SUBMENU ######

detection_test_menu() {

	while true; do
		clear
		detection_test_title "Detection-perspective testing - Stage 7 (close the loop)"

		if [ "${ifacemode}" = "Monitor" ]; then
			as_ui_kv "Interface" "${interface:-<none>} [Monitor]" ok
		else
			as_ui_kv "Interface" "${interface:-<none>} [${ifacemode:-Managed}]" warn
		fi
		if [ -n "${bssid}" ]; then
			as_ui_kv "Target AP" "${essid:-<hidden>} (${bssid}, ch ${channel})" ok
		else
			as_ui_kv "Target AP" "<none - lock a target>" warn
		fi
		if detection_test_is_active; then
			if [ "${detection_test_mode}" = "live" ]; then
				as_ui_kv "Mode" "live (ACTIVE)   Probe: ${detection_test_probe}   Count: ${detection_test_count}   Listen: ${detection_test_listen}s" err
			else
				as_ui_kv "Mode" "simulate (ACTIVE probe)   Probe: ${detection_test_probe}   Count: ${detection_test_count}" ok
			fi
		else
			as_ui_kv "Mode" "${detection_test_mode} (passive)   Probe: ${detection_test_probe}" ok
		fi
		case "${detection_test_probe}" in
			deauth)
				if [ -n "${detection_test_sta_mac}" ]; then as_ui_kv "Victim STA" "${detection_test_sta_mac}" ok
				else as_ui_kv "Victim STA" "<none - set via option 7>" warn; fi ;;
			pmf-check)
				if [ -n "${detection_test_rsn_caps}" ]; then as_ui_kv "RSN caps" "${detection_test_rsn_caps}" ok
				else as_ui_kv "RSN caps" "<none - set via option 8>" warn; fi ;;
			autojoin)
				if [ -n "${detection_test_csv}" ]; then as_ui_kv "CSV" "${detection_test_csv}" ok
				else as_ui_kv "CSV" "<none - set via option 9>" warn; fi ;;
		esac
		echo
		as_ui_sep
		as_ui_item 0 "Return to the WPA3 attacks menu"
		as_ui_section "Setup / target"
		as_ui_item 1 "Select wireless interface"
		as_ui_item 2 "Put adapter in monitor mode (if not already)"
		as_ui_item 3 "Explore for targets & lock target"
		as_ui_section "Probe"
		as_ui_item 4 "Run selected detection probe"
		as_ui_item 5 "Cycle probe (rogue-ap/deauth/pmf-check/autojoin)"
		as_ui_item 6 "Toggle mode (simulate <-> live)"
		as_ui_item 7 "Set victim client MAC (deauth probe)"
		as_ui_item 8 "Set RSN Capabilities (pmf-check probe)"
		as_ui_item 9 "Set airodump CSV (autojoin probe)"
		as_ui_item 10 "Set send count / listen window"
		echo

		read -rp "> " detection_option
		case "${detection_option}" in
			0) return ;;
			1) detection_test_select_interface ;;
			2) detection_test_ensure_monitor ;;
			3) detection_test_select_target ;;
			4) detection_test_run ;;
			5)
				case "${detection_test_probe}" in
					rogue-ap) detection_test_probe="deauth" ;;
					deauth) detection_test_probe="pmf-check" ;;
					pmf-check) detection_test_probe="autojoin" ;;
					*) detection_test_probe="rogue-ap" ;;
				esac
			;;
			6)
				if [ "${detection_test_mode}" = "simulate" ]; then detection_test_mode="live"; else detection_test_mode="simulate"; fi
			;;
			7) detection_test_set_sta_mac ;;
			8) detection_test_set_rsn_caps ;;
			9) detection_test_set_csv ;;
			10)
				read -rp "$(echo -e "${green_color}Frames to send [current ${detection_test_count}]: ${normal_color}")" _cnt
				if [[ "${_cnt}" =~ ^[0-9]+$ ]] && [ "${_cnt}" -gt 0 ]; then detection_test_count="${_cnt}"; else echo -e "${red_color}Invalid.${normal_color}"; sleep 1; fi
				read -rp "$(echo -e "${green_color}Listen window seconds [current ${detection_test_listen}]: ${normal_color}")" _lis
				if [[ "${_lis}" =~ ^[0-9]+$ ]] && [ "${_lis}" -gt 0 ]; then detection_test_listen="${_lis}"; else echo -e "${red_color}Invalid.${normal_color}"; sleep 1; fi
			;;
			*) echo -e "${red_color}Invalid option.${normal_color}"; sleep 1 ;;
		esac
	done
}
