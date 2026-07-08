#!/usr/bin/env bash
# First-time setup for Linux / Omarchy
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "=== FOCP Secure SDLC Assistant — Linux install ==="

command -v python3 >/dev/null || { echo "Install python3 first (pacman -S python on Arch/Omarchy)"; exit 1; }

python3 -m venv .venv
# shellcheck source=/dev/null
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"

chmod +x RUN-ON-LINUX.sh RUN-ON-LINUX-GUI.sh

echo ""
echo "Done. Run:"
echo "  ./RUN-ON-LINUX.sh scan /path/to/project"
echo "  ./RUN-ON-LINUX-GUI.sh          # optional GUI"
