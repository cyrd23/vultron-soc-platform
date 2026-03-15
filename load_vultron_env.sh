#!/usr/bin/env bash
set -euo pipefail
source "${HOME}/soc/.venv/bin/activate"
set -a
source "${HOME}/soc/configs/elastic.env"
set +a
echo "Vultron environment loaded."
