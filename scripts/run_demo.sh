#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN="python"
fi
"$PYTHON_BIN" tools/make_sample_data.py
"$PYTHON_BIN" -m sapauth --data sample_data --out out --today 2026-10-15