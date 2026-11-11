#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ "${1:-}" == '--help' ]]; then echo 'Usage: scripts/provision-admin.sh "Organization Name" admin@example.com'; exit 0; fi
[[ -f .env ]] || { echo 'Run scripts/install.sh first' >&2; exit 1; }
[[ $# -eq 2 ]] || { echo 'Usage: scripts/provision-admin.sh "Organization Name" admin@example.com' >&2; exit 2; }
# Password requested by Python getpass in the interactive container; not placed in shell history.
docker compose --env-file .env run --rm -it -e LEXIGRID_ADMIN_CONFIRM=YES migrate python -m app.admin_cli create-tenant --name "$1" --email "$2" --role platform_admin
