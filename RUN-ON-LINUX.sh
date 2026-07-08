#!/usr/bin/env bash
# =============================================================================
# FOCP Secure SDLC Assistant — LINUX / OMARCHY (Terminal CLI)
# =============================================================================
# Run this on: Arch Linux, Omarchy, Ubuntu, Fedora, or any Linux with bash.
#
# Usage:
#   ./RUN-ON-LINUX.sh                    # interactive menu
#   ./RUN-ON-LINUX.sh scan ./myproject   # scan a folder
#   ./RUN-ON-LINUX.sh score ./myproject
#   ./RUN-ON-LINUX.sh gui                # optional desktop GUI (needs display)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON="${PYTHON:-python3}"

# Colors for Omarchy / modern terminals
if [[ -t 1 ]]; then
  BOLD='\033[1m'
  CYAN='\033[0;36m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  RED='\033[0;31m'
  RESET='\033[0m'
else
  BOLD='' CYAN='' GREEN='' YELLOW='' RED='' RESET=''
fi

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║     FOCP Secure SDLC Assistant — Linux / Omarchy CLI      ║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

ensure_env() {
  if [[ ! -d "$VENV_DIR" ]]; then
    echo -e "${YELLOW}Creating virtual environment (.venv)...${RESET}"
    "$PYTHON" -m venv "$VENV_DIR"
  fi
  # shellcheck source=/dev/null
  source "$VENV_DIR/bin/activate"

  if ! python -c "import focp_sec" 2>/dev/null; then
    echo -e "${YELLOW}Installing dependencies (first run)...${RESET}"
    pip install -q --upgrade pip
    pip install -q -e "$SCRIPT_DIR"
  fi
}

run_cli() {
  ensure_env
  if [[ $# -eq 0 ]]; then
    echo -e "${GREEN}Examples:${RESET}"
    echo "  ./RUN-ON-LINUX.sh scan /path/to/project"
    echo "  ./RUN-ON-LINUX.sh score ./tests/sample_project"
    echo "  ./RUN-ON-LINUX.sh checklist ./myapp --type owasp"
    echo "  ./RUN-ON-LINUX.sh list-scans"
    echo ""
    echo -e "${CYAN}Running focp-sec --help${RESET}"
    echo ""
    exec focp-sec --help
  fi
  exec focp-sec "$@"
}

main() {
  banner
  run_cli "$@"
}

main "$@"
