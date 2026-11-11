#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Stop and deprovision services before removing application files.
MODE=native
if [[ -f "$ROOT/.lexigrid-deployment-mode" ]]; then IFS= read -r MODE < "$ROOT/.lexigrid-deployment-mode"; fi
if [[ "$MODE" == docker ]]; then
  if [[ -f "$ROOT/.env" ]] && command -v docker >/dev/null 2>&1; then
    docker compose --env-file "$ROOT/.env" -f "$ROOT/compose.yaml" down --remove-orphans
  else
    echo 'ERROR: Docker deployment cannot be stopped safely; cleanup aborted.' >&2; exit 1
  fi
else
  python3 "$ROOT/scripts/native/manager.py" stop
fi
python3 "$ROOT/scripts/uninstall_cleanup.py" --root "$ROOT" "$@"
