$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
python tools/make_sample_data.py
python -m sapauth --data sample_data --out out --today 2026-10-15