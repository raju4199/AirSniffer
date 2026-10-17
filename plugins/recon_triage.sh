#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### Airsniffer plugin: Recon & Target Triage ######
#
# Adds a "Recon & Target Triage" entry to the WPA3 attacks menu. It drives the
# recon_triage_engine.py analyzer, which turns a *passive* airodump-ng CSV scan
# into a red-team target-prioritisation report: per-AP security posture, weakest
# clients (WPA2 downgrade path on transition nets), evil-twin/Karma openings
# (probed SSIDs), and a recommended attack path per target mapped to the right
# Airsniffer module.
#
# This is a passive, non-transmitting stage - it reads a capture, it does not
# touch the air. No authorization gate is needed to read your own scan, but the
# attacks it recommends do require authorization; the report says so.
#
# AUTHORIZED USE ONLY.

###### GENERIC PLUGIN VARS ######

plugin_name="Recon & Target Triage"
plugin_description="Prioritise a passive airodump-ng scan into a red-team target list with per-AP attack paths"
plugin_author="Airsniffer"

plugin_enabled=1
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)/airsniffer_ui.sh" 2> /dev/null || true

###### PLUGIN REQUIREMENTS ######

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

###### WPA3 MENU REGISTRATION ######

recon_triage_menu_string_id=9120

#Locate the python engine next to this plugin at source time.
recon_triage_plugin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
recon_triage_engine="${recon_triage_plugin_dir}/recon_triage_engine.py"

#Session state: last CSV the operator pointed at.
recon_triage_csv=""

recon_triage_register_labels() {
	local lang
	local label="Recon & Target Triage (prioritise a passive airodump-ng scan)"
	for lang in ENGLISH SPANISH FRENCH CATALAN PORTUGUESE RUSSIAN GREEK ITALIAN POLISH GERMAN TURKISH ARABIC CHINESE; do
		arr["${lang}",${recon_triage_menu_string_id}]="${label}"
	done
}
recon_triage_register_labels

plugin_wpa3_menu_option_function="recon_triage_menu"
plugin_wpa3_menu_option_language_string="${recon_triage_menu_string_id}"

###### HELPERS ######

recon_triage_title() {
	as_ui_header "${1}"
}

recon_triage_pause() {
	as_ui_pause
}

#Resolve a usable python interpreter.
recon_triage_python() {
	if command -v python3 > /dev/null 2>&1; then
		echo "python3"
	elif command -v python > /dev/null 2>&1; then
		echo "python"
	else
		echo ""
	fi
}

#Try to auto-find the most recent airodump CSV Airsniffer has written this run.
#Airsniffer stores scan output under its tmpdir; fall back to the current dir.
recon_triage_autodetect_csv() {
	local candidate
	candidate="$(ls -t "${tmpdir:-/tmp/}"*.csv 2> /dev/null | head -n1)"
	[ -z "${candidate}" ] && candidate="$(ls -t ./*.csv 2> /dev/null | head -n1)"
	echo "${candidate}"
}

#Prompt for / confirm the CSV path to analyse.
recon_triage_select_csv() {
	local auto
	auto="$(recon_triage_autodetect_csv)"
	echo
	if [ -n "${auto}" ]; then
		echo -e "${blue_color}Most recent scan CSV found:${normal_color} ${auto}"
		read -rp "$(echo -e "${green_color}Use it? [Y/n] (or type another path): ${normal_color}")" _answer
		case "${_answer}" in
			""|y|Y|yes|YES) recon_triage_csv="${auto}" ;;
			n|N|no|NO)
				read -rp "$(echo -e "${green_color}Path to airodump-ng CSV: ${normal_color}")" recon_triage_csv
			;;
			*) recon_triage_csv="${_answer}" ;;
		esac
	else
		echo -e "${yellow_color}No scan CSV auto-detected.${normal_color}"
		echo -e "Run a scan first (Explore for targets), or airodump-ng with"
		echo -e "--output-format csv, then point here."
		read -rp "$(echo -e "${green_color}Path to airodump-ng CSV: ${normal_color}")" recon_triage_csv
	fi
	if [ -n "${recon_triage_csv}" ] && [ -f "${recon_triage_csv}" ]; then
		echo -e "${green_color}Selected:${normal_color} ${recon_triage_csv}"
	else
		echo -e "${red_color}File not found:${normal_color} ${recon_triage_csv:-<none>}"
		recon_triage_csv=""
	fi
	recon_triage_pause
}

#Run the analyzer against the selected CSV.
#$1 = output format: text | json
recon_triage_run() {
	local fmt="${1:-text}"
	local py
	py="$(recon_triage_python)"

	if [ -z "${py}" ]; then
		echo -e "${red_color}Python 3 not found.${normal_color} Install python3 to use this module."
		recon_triage_pause
		return
	fi
	if [ ! -f "${recon_triage_engine}" ]; then
		echo -e "${red_color}Engine not found:${normal_color} ${recon_triage_engine}"
		recon_triage_pause
		return
	fi
	if [ -z "${recon_triage_csv}" ] || [ ! -f "${recon_triage_csv}" ]; then
		echo -e "${red_color}No CSV selected.${normal_color} Use option 1 first."
		recon_triage_pause
		return
	fi

	echo
	if [ "${fmt}" = "json" ]; then
		local out="${tmpdir:-/tmp/}recon_triage.json"
		if "${py}" "${recon_triage_engine}" "${recon_triage_csv}" --json > "${out}"; then
			echo -e "${green_color}JSON report written:${normal_color} ${out}"
		else
			echo -e "${red_color}Analyzer failed.${normal_color} Is this an airodump-ng CSV?"
		fi
	else
		"${py}" "${recon_triage_engine}" "${recon_triage_csv}" || \
			echo -e "${red_color}Analyzer failed.${normal_color} Is this an airodump-ng CSV?"
	fi
	recon_triage_pause
}

###### SUBMENU ######

recon_triage_menu() {

	while true; do
		clear
		recon_triage_title "Recon & Target Triage - prioritise a passive scan"

		if [ -n "${recon_triage_csv}" ]; then
			as_ui_kv "Scan CSV" "${recon_triage_csv}" ok
		else
			as_ui_kv "Scan CSV" "<none - select a scan first>" err
		fi
		echo
		as_ui_sep
		as_ui_item 0 "Return to the WPA3 attacks menu"
		as_ui_section "Triage"
		as_ui_item 1 "Select airodump-ng scan CSV (auto-detect latest)"
		as_ui_item 2 "Triage report (prioritised targets + attack paths)"
		as_ui_item 3 "Export machine-readable JSON report"
		echo

		read -rp "> " recon_option
		case "${recon_option}" in
			0) return ;;
			1) recon_triage_select_csv ;;
			2) recon_triage_run "text" ;;
			3) recon_triage_run "json" ;;
			*)
				echo -e "${red_color}Invalid option.${normal_color}"
				sleep 1
			;;
		esac
	done
}
