#!/usr/bin/env bash
#
# Airsniffer shared UI library
# ============================
# Reusable terminal-UI primitives so every Airsniffer plugin shares one clean,
# modern look instead of each re-rolling its own headers/panels. Reuses
# airgeddon's existing color variables when present, and falls back to sane
# defaults so the library also renders when sourced standalone (e.g. in tests).
#
# This file is NOT an Airsniffer plugin: it intentionally does not set
# plugin_enabled=1, so parse_plugins() skips it. Plugins source it by path.
#
# Box-drawing uses Unicode by default; set AIRSNIFFER_UI_ASCII=1 for a pure-ASCII
# fallback on terminals that cannot render it.

#shellcheck disable=SC2034,SC2154

# Guard against double-sourcing.
if [ -n "${AS_UI_LOADED:-}" ]; then
	return 0 2> /dev/null || true
fi
AS_UI_LOADED=1

# --- Colors -----------------------------------------------------------------
# Reuse airgeddon's vars if already defined; otherwise define ANSI fallbacks so
# the library works standalone. : "${var:=default}" only sets when unset/empty.
if [ -t 1 ] || [ -n "${AS_UI_FORCE_COLOR:-}" ]; then
	: "${normal_color:=$'\033[0m'}"
	: "${red_color:=$'\033[1;31m'}"
	: "${green_color:=$'\033[1;32m'}"
	: "${yellow_color:=$'\033[1;33m'}"
	: "${blue_color:=$'\033[1;34m'}"
	: "${pink_color:=$'\033[1;35m'}"
	: "${cyan_color:=$'\033[1;36m'}"
	: "${white_color:=$'\033[1;37m'}"
else
	: "${normal_color:=}"; : "${red_color:=}"; : "${green_color:=}"
	: "${yellow_color:=}"; : "${blue_color:=}"; : "${pink_color:=}"
	: "${cyan_color:=}"; : "${white_color:=}"
fi
# airgeddon may not define cyan/white; ensure they exist for our accents.
: "${cyan_color:=${blue_color}}"
: "${white_color:=${normal_color}}"

# --- Box characters (Unicode with ASCII fallback) ---------------------------
if [ "${AIRSNIFFER_UI_ASCII:-0}" = "1" ]; then
	AS_TL='+'; AS_TR='+'; AS_BL='+'; AS_BR='+'; AS_H='-'; AS_V='|'
	AS_ML='+'; AS_MR='+'; AS_DOT='*'; AS_ARROW='>'; AS_OKC='+'; AS_ERRC='x'
	AS_WARNC='!'; AS_DOTC='o'
else
	AS_TL='╔'; AS_TR='╗'; AS_BL='╚'; AS_BR='╝'; AS_H='═'; AS_V='║'
	AS_ML='╟'; AS_MR='╢'; AS_DOT='•'; AS_ARROW='▸'; AS_OKC='✓'; AS_ERRC='✗'
	AS_WARNC='!'; AS_DOTC='●'
fi

AS_UI_WIDTH="${AS_UI_WIDTH:-58}"

# Repeat a string N times.
as_ui_repeat() { local i s=""; for ((i = 0; i < ${2:-0}; i++)); do s+="${1}"; done; printf '%s' "${s}"; }

# --- Header box -------------------------------------------------------------
# as_ui_header "Title" ["subtitle"]
as_ui_header() {
	local title="${1}" sub="${2:-}" w="${AS_UI_WIDTH}"
	local bar; bar="$(as_ui_repeat "${AS_H}" "$((w - 2))")"
	echo
	echo -e "${pink_color}${AS_TL}${bar}${AS_TR}${normal_color}"
	printf "${pink_color}${AS_V}${normal_color} ${cyan_color}%-*s${normal_color} ${pink_color}${AS_V}${normal_color}\n" "$((w - 4))" "${title}"
	if [ -n "${sub}" ]; then
		printf "${pink_color}${AS_V}${normal_color} ${blue_color}%-*s${normal_color} ${pink_color}${AS_V}${normal_color}\n" "$((w - 4))" "${sub}"
	fi
	echo -e "${pink_color}${AS_BL}${bar}${AS_BR}${normal_color}"
}

# --- Compact brand banner ---------------------------------------------------
as_ui_banner() {
	local w="${AS_UI_WIDTH}"; local bar; bar="$(as_ui_repeat "${AS_H}" "$((w - 2))")"
	echo -e "${pink_color}${AS_TL}${bar}${AS_TR}${normal_color}"
	printf "${pink_color}${AS_V}${normal_color}  ${cyan_color}A I R S N I F F E R${normal_color}  ${blue_color}%s${normal_color}%*s${pink_color}${AS_V}${normal_color}\n" \
		"wireless security toolkit" "$((w - 49))" ""
	echo -e "${pink_color}${AS_BL}${bar}${AS_BR}${normal_color}"
}

# --- Separator --------------------------------------------------------------
as_ui_sep() {
	echo -e "${blue_color}$(as_ui_repeat "${AS_H}" "${1:-${AS_UI_WIDTH}}")${normal_color}"
}

# --- Section subheader ------------------------------------------------------
# as_ui_section "Setup / target"
as_ui_section() {
	echo -e "${yellow_color}${AS_ARROW} ${1}${normal_color}"
}

# --- Key : value panel line, with optional state coloring -------------------
# as_ui_kv "Label" "Value" [ok|warn|err|info|dim]
as_ui_kv() {
	local label="${1}" value="${2}" state="${3:-info}" vc
	case "${state}" in
		ok)   vc="${green_color}" ;;
		warn) vc="${yellow_color}" ;;
		err)  vc="${red_color}" ;;
		dim)  vc="${blue_color}" ;;
		*)    vc="${normal_color}" ;;
	esac
	printf "${blue_color}%-11s${normal_color}${pink_color}${AS_V}${normal_color} ${vc}%s${normal_color}\n" "${label}" "${value}"
}

# --- Status badge -----------------------------------------------------------
# as_ui_badge ok|err|warn|info "text"
as_ui_badge() {
	local kind="${1}" text="${2}"
	case "${kind}" in
		ok)   echo -e "${green_color}[${AS_OKC}]${normal_color} ${text}" ;;
		err)  echo -e "${red_color}[${AS_ERRC}]${normal_color} ${text}" ;;
		warn) echo -e "${yellow_color}[${AS_WARNC}]${normal_color} ${text}" ;;
		*)    echo -e "${cyan_color}[${AS_DOTC}]${normal_color} ${text}" ;;
	esac
}

# --- Menu row ---------------------------------------------------------------
# as_ui_item "4" "Run selected strategy"
as_ui_item() {
	printf " ${green_color}%2s.${normal_color} ${normal_color}%s${normal_color}\n" "${1}" "${2}"
}

# --- Inline message helpers -------------------------------------------------
as_ui_ok()   { echo -e "${green_color}${AS_OKC} ${1}${normal_color}"; }
as_ui_err()  { echo -e "${red_color}${AS_ERRC} ${1}${normal_color}"; }
as_ui_warn() { echo -e "${yellow_color}${AS_WARNC} ${1}${normal_color}"; }
as_ui_note() { echo -e "${cyan_color}${AS_DOT} ${1}${normal_color}"; }

# --- Styled pause -----------------------------------------------------------
as_ui_pause() {
	echo
	read -rp "$(echo -e "${yellow_color}${AS_ARROW} Press [Enter] to continue...${normal_color}")" _as_ui_pause
}

# --- Prompt (returns value in REPLY-style var via echo) ---------------------
as_ui_prompt() {
	# as_ui_prompt "Question"  -> prints colored prompt, caller reads into var
	printf "%s" "$(echo -e "${green_color}${AS_ARROW} ${1}${normal_color}")"
}
