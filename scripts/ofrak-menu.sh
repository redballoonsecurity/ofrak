#!/usr/bin/env bash
# ==============================================================
#  OFRAK Terminal Menu (TUI)
#  Interactive terminal interface for OFRAK - no browser needed.
#  Works anywhere: Termux, Linux desktop, AppImage, etc.
# ==============================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

command -v ofrak >/dev/null 2>&1 || { echo -e "${RED}ofrak not found in PATH${NC}"; exit 1; }

WORKDIR="$(pwd)/ofrak-output"
mkdir -p "$WORKDIR"

pause() { echo ""; read -r -p "Tekan Enter untuk lanjut..." _; }

do_unpack() {
    local rec="$1"
    echo -e "${CYAN}${BOLD}--- UNPACK ---${NC}"
    read -r -p "Path file yang mau di-unpack: " F
    [[ -f "$F" ]] || { echo -e "${RED}File tidak ditemukan: $F${NC}"; pause; return; }
    OUT="$WORKDIR/$(basename "$F")_unpacked"
    local args=(unpack "$F" -o "$OUT")
    [[ "$rec" == "-r" ]] && args+=(--recursive)
    echo -e "${CYAN}Output: $OUT${NC}"
    ofrak "${args[@]}" && echo -e "${GREEN}✔ Selesai! Hasil di: $OUT${NC}" \
        || echo -e "${RED}✘ Gagal unpack (lihat error di atas)${NC}"
    # Show result tree
    if [[ -d "$OUT" ]]; then
        echo ""
        find "$OUT" -maxdepth 2 | head -40
    fi
    pause
}

do_identify() {
    echo -e "${CYAN}${BOLD}--- IDENTIFY FORMAT ---${NC}"
    read -r -p "Path file: " F
    [[ -f "$F" ]] || { echo -e "${RED}File tidak ditemukan${NC}"; pause; return; }
    ofrack identify "$F" || true
    pause
}

do_list() {
    ofrak list || true
    pause
}

do_license() {
    ofrak license --community --i-agree \
      && echo -e "${GREEN}✔ Community license accepted${NC}" \
      || echo -e "${RED}✘ Gagal accept license${NC}"
    pause
}

do_gui() {
    echo -e "${YELLOW}Starting web GUI di http://127.0.0.1:8888 (Ctrl-C untuk stop)${NC}"
    ofrak gui || true
    pause
}

while true; do
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║   OFRAK  •  Terminal Menu (TUI)       ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}File:${NC} ${1:-<pakai menu>}"
    echo ""
    echo -e "  ${GREEN}1${NC}) Unpack file (recursive)"
    echo -e "  ${GREEN}2${NC}) Unpack file (single level)"
    echo -e "  ${GREEN}3${NC}) Identify format file"
    echo -e "  ${GREEN}4${NC}) List semua komponen OFRAK"
    echo -e "  ${GREEN}5${NC}) Accept community license"
    echo -e "  ${GREEN}6${NC}) Start web GUI (opsional/browser)"
    echo -e "  ${GREEN}7${NC}) Hexdump file"
    echo -e "  ${RED}0${NC}) Keluar"
    echo ""
    read -r -p "  Pilih: " choice
    case "$choice" in
        1) do_unpack "-r" ;;
        2) do_unpack "" ;;
        3) do_identify ;;
        4) do_list ;;
        5) do_license ;;
        6) do_gui ;;
        7) read -r -p "Path file: " HF
           if [[ -f "$HF" ]]; then hexdump -C "$HF" | head -60; else echo -e "${RED}Tidak ketemu${NC}"; fi
           pause ;;
        0) exit 0 ;;
        *) : ;;
    esac
done
