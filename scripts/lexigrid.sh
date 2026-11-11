#!/usr/bin/env bash
# LexiGrid lifecycle management. Shahryar Jahangir / Aniza Inc.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose --env-file "$ROOT/.env" -f "$ROOT/compose.yaml")
fail(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null || fail "Missing required command: $1"; }
check_env(){ [[ -f .env ]] || fail "Missing .env; run install first"; chmod 600 .env; }
compose(){ "${COMPOSE[@]}" "$@"; }
random_secret(){ python3 -c 'import secrets;print(secrets.token_hex(32))'; }
install(){
  need docker; need python3
  docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable'
  docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 required'
  if [[ ! -f .env ]]; then
    (umask 077; touch .env)
    for key in POSTGRES_OWNER_PASSWORD RUNTIME_DB_PASSWORD JWT_SECRET AUDIT_HMAC_KEY EVIDENCE_ENCRYPTION_KEY LEXIGRID_MFA_ENCRYPTION_KEY LEXIGRID_MAIL_CONFIG_KEY LEXIGRID_ANCHOR_HMAC_KEY; do
      if [[ "$key" == LEXIGRID_MFA_ENCRYPTION_KEY || "$key" == LEXIGRID_MAIL_CONFIG_KEY ]]; then
        value="$(python3 -c 'import base64,secrets;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')"
      else
        value="$(random_secret)"
      fi
      printf '%s=%s\n' "$key" "$value" >> .env
    done
    printf '%s\n' 'LEXIGRID_KMS_PROVIDER=local' 'LEXIGRID_WORKFLOW_SCAN_SECONDS=300' 'LEXIGRID_REQUIRE_MFA=1' 'LEXIGRID_REQUIRE_LOCAL_MFA=0' >> .env
    echo 'Generated .env with independent secrets (mode 600). Back up securely.'
  else
    if ! grep -q '^LEXIGRID_MAIL_CONFIG_KEY=' .env; then
      value="$(python3 -c 'import base64,secrets;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')"
      printf '\nLEXIGRID_MAIL_CONFIG_KEY=%s\n' "$value" >> .env
      chmod 600 .env
      echo 'Generated new mail configuration encryption key; existing secrets retained.'
    fi
    echo 'Existing .env retained; secrets will not be overwritten.'
  fi
  check_env
  python3 "$ROOT/scripts/configure_ai.py" --mode docker --config "$ROOT/.env"
  compose config --quiet || fail 'Compose configuration invalid'
  echo 'Existing database volume will be preserved. Schema migrations will run during startup.'
  compose up -d --build --wait postgres
  compose run --rm migrate
  compose up -d --build --no-deps api workflow-scheduler
  status
  echo 'Bootstrap first tenant administrator with scripts/provision-admin.sh (see administration guide).'
}
start(){ need docker; check_env; compose up -d postgres; compose run --rm migrate; compose up -d --no-deps api workflow-scheduler; status; }
stop(){ need docker; check_env; compose stop api workflow-scheduler postgres; }
status(){ need docker; check_env; compose ps; if compose ps --status running --services | grep -qx api; then
  if command -v curl >/dev/null && curl --silent --fail --max-time 4 http://127.0.0.1:8000/health >/dev/null; then echo 'API health: HEALTHY'; else echo 'API health: NOT READY'; fi
else echo 'API health: NOT RUNNING'; fi; }
uninstall(){
  need docker; check_env
  echo 'This removes application containers. Data is retained unless you explicitly choose DELETE.'
  read -r -p 'Type UNINSTALL to proceed: ' answer
  [[ "$answer" == UNINSTALL ]] || fail 'Cancelled'
  compose down --remove-orphans
  read -r -p 'Delete PostgreSQL volume permanently? Type DELETE DATA to confirm, or Enter to keep: ' answer
  if [[ "$answer" == 'DELETE DATA' ]]; then
    read -r -p 'FINAL CONFIRMATION: type ERASE LEXIGRID DATABASE: ' final
    [[ "$final" == 'ERASE LEXIGRID DATABASE' ]] || fail 'Database retained; cancellation of deletion'
    compose down -v --remove-orphans
    echo 'Database volume deleted.'
  else echo 'Database volume preserved.'; fi
  echo '.env secrets preserved; remove manually only after confirming no recovery is required.'
}
# Deployment selection is persisted so subsequent lifecycle commands use the same mode.
MODE_FILE="$ROOT/.lexigrid-deployment-mode"
ACTION="${1:-}"
[[ $# -gt 0 ]] && shift
MODE=""
NATIVE_ARGS=()
NATIVE_ARGS_PRESENT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) [[ $# -ge 2 ]] || fail '--mode requires native or docker'; MODE="$2"; shift 2;;
    --mode=*) MODE="${1#*=}"; shift;;
    --native) MODE=native; shift;;
    --docker) MODE=docker; shift;;
    --database|--database-url|--pg-host|--pg-port|--pg-database|--pg-user|--pg-password) [[ $# -ge 2 ]] || fail "$1 requires a value"; NATIVE_ARGS+=("$1" "$2"); NATIVE_ARGS_PRESENT=1; shift 2;;
    --database=*|--database-url=*|--pg-host=*|--pg-port=*|--pg-database=*|--pg-user=*|--pg-password=*) NATIVE_ARGS+=("$1"); NATIVE_ARGS_PRESENT=1; shift;;
    --skip-migrations) NATIVE_ARGS+=("$1"); NATIVE_ARGS_PRESENT=1; shift;;
    *) fail "Unknown argument: $1";;
  esac
done
if [[ -z "$MODE" && -f "$MODE_FILE" ]]; then MODE="$(cat "$MODE_FILE")"; fi
if [[ -z "$MODE" && "$ACTION" == install ]]; then
  if [[ ! -t 0 ]]; then
    fail 'Noninteractive installation requires --mode native or --mode docker'
  fi
  echo 'Select LexiGrid installation type:'
  echo '  1) Native Python (no Docker; SQLite development default or external PostgreSQL)'
  echo '  2) Docker Compose (requires Docker engine and Compose v2)'
  read -r -p 'Choose 1 or 2: ' selection
  case "$selection" in 1) MODE=native;; 2) MODE=docker;; *) fail 'Invalid selection';; esac
fi
[[ -n "$MODE" ]] || MODE=docker
[[ "$MODE" == native || "$MODE" == docker ]] || fail 'Mode must be native or docker'
if [[ "$MODE" == docker && "$NATIVE_ARGS_PRESENT" -eq 1 ]]; then fail "Database selection flags apply to native mode only; Docker Compose uses its PostgreSQL service"; fi
if [[ "$MODE" == native ]]; then
  need python3
  case "$ACTION" in install|start|stop|status|uninstall) ;;
    *) fail 'Usage: scripts/lexigrid.sh {install|start|stop|status|uninstall} [--mode native|docker]' ;;
  esac
  # macOS ships Bash 3.2: with set -u, expanding an empty array fails.
  if [[ "$NATIVE_ARGS_PRESENT" -eq 1 ]]; then
    python3 "$ROOT/scripts/native/manager.py" "$ACTION" "${NATIVE_ARGS[@]}"
  else
    python3 "$ROOT/scripts/native/manager.py" "$ACTION"
  fi
  if [[ "$ACTION" == install ]]; then
    python3 "$ROOT/scripts/configure_ai.py" --mode native --config "$ROOT/.env.native"
    printf 'native\n' > "$MODE_FILE"
  fi
  exit 0
fi
# Check Docker only after the user has selected Docker mode.
if [[ "$ACTION" == install ]]; then
  install
  printf 'docker\n' > "$MODE_FILE"
  exit 0
fi
case "${ACTION}" in
 install) install;; start) start;; stop) stop;; status) status;; uninstall) uninstall;;
 *) echo 'Usage: scripts/lexigrid.sh {install|start|stop|status|uninstall}' >&2; exit 2;;
esac
