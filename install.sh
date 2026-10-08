#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${HOME}/.local/bin/ip-info"

mkdir -p "${HOME}/.local/bin"
ln -sf "${SCRIPT_DIR}/ip_info.py" "${TARGET}"
chmod +x "${SCRIPT_DIR}/ip_info.py"

echo "Installed: ip-info → ${TARGET}"
