#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### Airsniffer plugin: Fuzzing DoS ######
#
# Adds a "Fuzzing DoS" session to the WPA3 attacks menu. It drives an 802.11
# fuzzing engine (WPAxFuzz-style: Kampourakis et al., Cryptography 2022) that
# stresses management, control and WPA3-SAE frames to trigger firmware DoS bugs
# in Access Points / Stations. Unlike a plain deauth attack, this class of DoS
# keeps working against WPA3/PMF networks because it abuses frames PMF does not
# protect and firmware parsing flaws rather than the deauth/disassoc frames.
#
# Two execution modes, toggled from the menu:
#   * SIMULATION (default, safe) - crafts and logs every frame that WOULD be
#     sent, runs the full batch/monitoring/attack-module flow, transmits
#     nothing. No hardware, root or scapy needed. Great for demos and learning.
#   * LIVE - real scapy frame injection on a monitor-mode interface (Linux +
#     root). Gated behind an explicit authorization prompt.
#
# AUTHORIZED USE ONLY.

###### GENERIC PLUGIN VARS ######

plugin_name="Fuzzing DoS"
plugin_description="WPAxFuzz-style 802.11 management/control/SAE fuzzing DoS with simulation and live modes"
plugin_author="Airsniffer"

plugin_enabled=1
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)/airsniffer_ui.sh" 2> /dev/null || true

###### PLUGIN REQUIREMENTS ######

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

###### WPA3 MENU REGISTRATION ######

fuzzing_dos_menu_string_id=9110

#Capture the plugin directory at source time so we can locate the python engine.
fuzzing_dos_plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
fuzzing_dos_engine="${fuzzing_dos_plugin_dir}/fuzzing_dos_engine.py"

#Session state (menu-toggled).
fuzzing_dos_mode="simulate"     # simulate | live
fuzzing_dos_fuzz_mode="random"  # random | standard
fuzzing_dos_target="ap"         # ap | sta
fuzzing_dos_sta_mac=""          # victim client MAC (required for 'sta' direction)
fuzzing_dos_authorized=0

fuzzing_dos_register_labels() {
	local lang
	local label="Fuzzing DoS (WPAxFuzz-style management/control/SAE fuzzer) *"
	for lang in ENGLISH SPANISH FRENCH CATALAN PORTUGUESE RUSSIAN GREEK ITALIAN POLISH GERMAN TURKISH ARABIC CHINESE; do
		arr["${lang}",${fuzzing_dos_menu_string_id}]="${label}"
	done
}
fuzzing_dos_register_labels

plugin_wpa3_menu_option_function="fuzzing_dos_menu"
plugin_wpa3_menu_option_language_string="${fuzzing_dos_menu_string_id}"

###### HELPERS ######

fuzzing_dos_title() {
	as_ui_header "${1}"
}

fuzzing_dos_pause() {
	as_ui_pause
}

#Validate a MAC: six colon-separated hex octets.
fuzzing_dos_valid_mac() {
	[[ "${1}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

#Prompt for the victim client MAC used by the 'sta' direction.
fuzzing_dos_set_sta_mac() {
	local mac
	read -rp "$(echo -e "${green_color}Target client MAC (AA:BB:CC:DD:EE:FF, blank to clear): ${normal_color}")" mac
	if [ -z "${mac}" ]; then
		fuzzing_dos_sta_mac=""
		echo -e "${yellow_color}Cleared.${normal_color} 'sta' direction will have no real victim set."
	elif fuzzing_dos_valid_mac "${mac}"; then
		fuzzing_dos_sta_mac="${mac}"
		echo -e "${green_color}Victim client MAC set:${normal_color} ${fuzzing_dos_sta_mac}"
	else
		echo -e "${red_color}Invalid MAC format.${normal_color} Not changed."
	fi
	fuzzing_dos_pause
}

#Resolve a usable python interpreter.
fuzzing_dos_python() {
	if command -v python3 > /dev/null 2>&1; then
		echo "python3"
	elif command -v python > /dev/null 2>&1; then
		echo "python"
	else
		echo ""
	fi
}

#Authorization gate - required only before LIVE runs.
fuzzing_dos_authorization_gate() {
	if [ "${fuzzing_dos_authorized}" -eq 1 ]; then
		return 0
	fi
	echo
	echo -e "${red_color}LIVE MODE - AUTHORIZED TESTING ONLY${normal_color}"
	echo -e "${yellow_color}Live mode injects real frames and can disconnect devices. Only run it"
	echo -e "against networks you own or are explicitly authorized to test.${normal_color}"
	echo
	read -rp "$(echo -e "${green_color}Do you have authorization for this target? [y/N]: ${normal_color}")" _auth
	case "${_auth}" in
		y|Y|yes|YES) fuzzing_dos_authorized=1; return 0 ;;
		*) echo; echo -e "${red_color}Aborted. Authorization is required for live mode.${normal_color}"; return 1 ;;
	esac
}

#Build the common engine arguments into the fuzzing_dos_args array. Using an
#array (not a space-joined string) keeps values with spaces intact - e.g. an
#ESSID like "Home Y28 5G" stays one --ssid value instead of being word-split.
fuzzing_dos_build_args() {
	local outdir="${1}"
	#The core has no single "selected client" variable, so the victim station
	#MAC is set explicitly via the menu. Fall back to a placeholder only so
	#simulation can run; the 'sta' direction warns when it is unset.
	local sta_mac="${fuzzing_dos_sta_mac:-BB:BB:BB:BB:BB:BB}"
	fuzzing_dos_args=(
		--mode "${fuzzing_dos_mode}"
		--fuzz-mode "${fuzzing_dos_fuzz_mode}"
		--target "${fuzzing_dos_target}"
		--iface "${interface:-wlan0mon}"
		--ap-mac "${bssid:-AA:AA:AA:AA:AA:AA}"
		--sta-mac "${sta_mac}"
		--ssid "${essid:-TARGET_SSID}"
		--channel "${channel:-1}"
		--logdir "${outdir}"
	)
}

#Setup step: pick the wireless interface using Airsniffer's core selector.
fuzzing_dos_select_interface() {
	select_interface
	fuzzing_dos_pause
}

#Setup step: put the adapter in monitor mode, but only if it is not already.
#Reuses Airsniffer's monitor_option and the core ifacemode state variable.
fuzzing_dos_ensure_monitor() {
	if [ -z "${interface}" ]; then
		echo
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 (select interface) first."
		fuzzing_dos_pause
		return 1
	fi
	if [ "${ifacemode}" = "Monitor" ]; then
		echo
		echo -e "${green_color}${interface} is already in monitor mode.${normal_color} Nothing to do."
		fuzzing_dos_pause
		return 0
	fi
	echo
	echo -e "${yellow_color}Putting ${interface} into monitor mode...${normal_color}"
	monitor_option "${interface}"
	fuzzing_dos_pause
}

#Setup step: scan the air, list APs and lock onto one target.
#explore_for_targets_option sets bssid/essid/channel/enc for the whole session.
fuzzing_dos_select_target() {
	if [ -z "${interface}" ]; then
		echo
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 (select interface) first."
		fuzzing_dos_pause
		return 1
	fi
	if [ "${ifacemode}" != "Monitor" ]; then
		echo
		echo -e "${yellow_color}${interface} is not in monitor mode.${normal_color} Enabling it first..."
		if ! monitor_option "${interface}"; then
			fuzzing_dos_pause
			return 1
		fi
	fi
	explore_for_targets_option "WPA3"
	if [ -n "${bssid}" ]; then
		echo
		echo -e "${green_color}Target locked:${normal_color} ${essid:-<hidden>} (${bssid}, ch ${channel})"
	fi
	fuzzing_dos_pause
}

#Guard: attacks need a locked target. Warn (and block live) when none is set.
fuzzing_dos_require_target() {
	if [ -n "${bssid}" ]; then
		return 0
	fi
	echo
	echo -e "${red_color}No target locked.${normal_color} Use option 3 (explore & lock target) first."
	if [ "${fuzzing_dos_mode}" = "simulate" ]; then
		echo -e "${yellow_color}Simulation will use placeholder values instead.${normal_color}"
		return 0
	fi
	fuzzing_dos_pause
	return 1
}

#Guard: live mode needs a selected interface + target.
fuzzing_dos_live_prereqs_ok() {
	if [ -z "${interface}" ]; then
		echo -e "${red_color}No interface selected.${normal_color} Use option 1 (select interface) first."
		return 1
	fi
	if [ "${ifacemode}" != "Monitor" ]; then
		echo -e "${red_color}${interface} is not in monitor mode.${normal_color} Use option 2 first."
		return 1
	fi
	if [ -z "${bssid}" ]; then
		echo -e "${red_color}No target locked.${normal_color} Use option 3 (explore & lock target) first."
		return 1
	fi
	return 0
}

#Run the engine for a given --attack value, handling sim vs live launch.
#$1 = attack module (mgmt|control|sae|attack-module)  $2 = optional --frame
fuzzing_dos_run() {

	local attack="${1}"
	local frame="${2:-all}"
	local py
	py="$(fuzzing_dos_python)"

	if [ -z "${py}" ]; then
		echo -e "${red_color}Python 3 not found.${normal_color} Install python3 to use this module."
		fuzzing_dos_pause
		return
	fi
	if [ ! -f "${fuzzing_dos_engine}" ]; then
		echo -e "${red_color}Engine not found:${normal_color} ${fuzzing_dos_engine}"
		fuzzing_dos_pause
		return
	fi

	local outdir="${tmpdir:-/tmp/}fuzzing_dos"
	mkdir -p "${outdir}" 2> /dev/null

	#The 'sta' direction sends frames TO a victim client; without a real client
	#MAC the frames go nowhere. Warn (simulate) or block (live).
	if [ "${fuzzing_dos_target}" = "sta" ] && [ -z "${fuzzing_dos_sta_mac}" ]; then
		if [ "${fuzzing_dos_mode}" = "live" ]; then
			echo -e "${red_color}'sta' direction needs a target client MAC.${normal_color} Set it (option 11) first."
			fuzzing_dos_pause
			return
		fi
		echo -e "${yellow_color}No victim client MAC set - simulating toward a placeholder MAC.${normal_color}"
	fi

	local fuzzing_dos_args=()
	fuzzing_dos_build_args "${outdir}"

	if [ "${fuzzing_dos_mode}" = "live" ]; then
		if ! fuzzing_dos_authorization_gate; then
			fuzzing_dos_pause
			return
		fi
		if ! fuzzing_dos_live_prereqs_ok; then
			fuzzing_dos_pause
			return
		fi
		echo -e "${yellow_color}Setting ${interface} to channel ${channel}...${normal_color}"
		iw dev "${interface}" set channel "${channel}" > /dev/null 2>&1
		recalculate_windows_sizes 2> /dev/null
		#Build a properly shell-quoted command so values with spaces (e.g. the
		#ESSID) survive being run in a separate window via manage_output.
		local live_cmd
		printf -v live_cmd '%q ' "${py}" "${fuzzing_dos_engine}" \
			--attack "${attack}" --frame "${frame}" "${fuzzing_dos_args[@]}"
		#Launch live runs in their own window so the main UI stays responsive.
		manage_output "+j -bg \"#000000\" -fg \"#00FF00\" -T \"Fuzzing DoS (${attack})\"" \
			"${live_cmd}" \
			"Fuzzing DoS (${attack})"
		echo -e "${green_color}Live ${attack} run launched.${normal_color} Output/exploits: ${outdir}"
	else
		#Simulation runs inline so the operator sees the full flow immediately.
		echo -e "${blue_color}Running SIMULATION (nothing is transmitted)...${normal_color}"
		echo
		"${py}" "${fuzzing_dos_engine}" --attack "${attack}" --frame "${frame}" "${fuzzing_dos_args[@]}"
		echo
		echo -e "${green_color}Simulation output / generated exploits:${normal_color} ${outdir}"
	fi
	fuzzing_dos_pause
}

###### SUBMENU ######

fuzzing_dos_menu() {

	while true; do
		clear
		fuzzing_dos_title "Fuzzing DoS - WPAxFuzz-style 802.11 fuzzer"

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
		if [ "${fuzzing_dos_mode}" = "live" ]; then
			as_ui_kv "Mode" "live   Fuzz: ${fuzzing_dos_fuzz_mode}   Direction: ${fuzzing_dos_target}" err
		else
			as_ui_kv "Mode" "simulate   Fuzz: ${fuzzing_dos_fuzz_mode}   Direction: ${fuzzing_dos_target}" ok
		fi
		if [ "${fuzzing_dos_target}" = "sta" ]; then
			if [ -n "${fuzzing_dos_sta_mac}" ]; then
				as_ui_kv "Victim STA" "${fuzzing_dos_sta_mac}" ok
			else
				as_ui_kv "Victim STA" "<none - set via option 11>" err
			fi
		fi
		echo
		as_ui_sep
		as_ui_item 0 "Return to the WPA3 attacks menu"
		as_ui_section "Setup / target"
		as_ui_item 1 "Select wireless interface"
		as_ui_item 2 "Put adapter in monitor mode (if not already)"
		as_ui_item 3 "Explore for targets & lock target"
		as_ui_section "Attacks"
		as_ui_item 4 "Management-frame fuzzing (beacon/probe/assoc/auth)"
		as_ui_item 5 "Control-frame fuzzing (rts/cts/ack/bar/ba...)"
		as_ui_item 6 "WPA3-SAE fuzzing (Commit/Confirm variants)"
		as_ui_item 7 "Attack module (replay + auto-generate exploit)"
		as_ui_section "Session"
		as_ui_item 8 "Toggle mode (simulate <-> live)"
		as_ui_item 9 "Toggle fuzz mode (random <-> standard)"
		as_ui_item 10 "Toggle direction (ap <-> sta)"
		as_ui_item 11 "Set target client MAC (for 'sta' direction)"
		echo

		read -rp "> " fuzz_option
		case "${fuzz_option}" in
			0) return ;;
			1) fuzzing_dos_select_interface ;;
			2) fuzzing_dos_ensure_monitor ;;
			3) fuzzing_dos_select_target ;;
			4) fuzzing_dos_require_target && fuzzing_dos_run "mgmt" "all" ;;
			5) fuzzing_dos_require_target && fuzzing_dos_run "control" "all" ;;
			6) fuzzing_dos_require_target && fuzzing_dos_run "sae" "all" ;;
			7) fuzzing_dos_require_target && fuzzing_dos_run "attack-module" "all" ;;
			8)
				if [ "${fuzzing_dos_mode}" = "simulate" ]; then
					fuzzing_dos_mode="live"
				else
					fuzzing_dos_mode="simulate"
				fi
			;;
			9)
				if [ "${fuzzing_dos_fuzz_mode}" = "random" ]; then
					fuzzing_dos_fuzz_mode="standard"
				else
					fuzzing_dos_fuzz_mode="random"
				fi
			;;
			10)
				if [ "${fuzzing_dos_target}" = "ap" ]; then
					fuzzing_dos_target="sta"
				else
					fuzzing_dos_target="ap"
				fi
			;;
			11) fuzzing_dos_set_sta_mac ;;
			*)
				echo -e "${red_color}Invalid option.${normal_color}"
				sleep 1
			;;
		esac
	done
}
