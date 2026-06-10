#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 scripts/bootstrap_env.py
python3 run.py
