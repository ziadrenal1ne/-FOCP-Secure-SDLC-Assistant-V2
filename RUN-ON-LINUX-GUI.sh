#!/usr/bin/env bash
# =============================================================================
# FOCP Secure SDLC Assistant — LINUX / OMARCHY (Desktop GUI)
# =============================================================================
# Requires a graphical session (Wayland/X11). On Omarchy with Hyprland, use
# this from your terminal emulator (foot, kitty, alacritty, etc.).
#
# Usage:
#   ./RUN-ON-LINUX-GUI.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
  echo "ERROR: No display detected. On Linux/Omarchy use the terminal version instead:"
  echo "  ./RUN-ON-LINUX.sh scan /path/to/project"
  exit 1
fi

VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON="${PYTHON:-python3}"

if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON" -m venv "$VENV_DIR"
fi
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

if ! python -c "import focp_sec" 2>/dev/null; then
  pip install -q --upgrade pip
  pip install -q -e "$SCRIPT_DIR"
fi

exec focp-sec gui
