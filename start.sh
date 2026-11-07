#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ "$EUID" -eq 0 ]]; then
  echo "Start the dashboard as your normal desktop user, without sudo."
  exit 1
fi
cd -- "$(dirname -- "$0")"
if [[ ! -x .venv/bin/python ]]; then
  echo 'Install first: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt'
  exit 1
fi
exec .venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --browser.gatherUsageStats false "$@"
