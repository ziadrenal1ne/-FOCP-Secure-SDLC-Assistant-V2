#!/usr/bin/env bash
# Build standalone Linux CLI binary (PyInstaller)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=/dev/null
source .venv/bin/activate 2>/dev/null || { echo "Run platforms/linux/install.sh first"; exit 1; }

pip install -q pyinstaller

pyinstaller --onefile --name focp-sec-linux \
  --add-data "src/focp_sec/templates:focp_sec/templates" \
  --add-data "config.yaml:." \
  --paths src \
  --console \
  src/focp_sec/cli/main.py

echo ""
echo "Binary: dist/focp-sec-linux"
echo "Run:    ./dist/focp-sec-linux scan /path/to/project"
