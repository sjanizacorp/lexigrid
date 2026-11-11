#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_DIR="$HOME/LexiGrid"
INSTALL_DIR=""
UPDATE_EXISTING=0
PASS_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir|--location) [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a directory" >&2; exit 2; }; INSTALL_DIR="$2"; shift 2;;
    --install-dir=*|--location=*) INSTALL_DIR="${1#*=}"; shift;;
    --update-existing) UPDATE_EXISTING=1; shift;;
    *) PASS_ARGS+=("$1"); shift;;
  esac
done
if [[ -z "$INSTALL_DIR" ]]; then
  if [[ -t 0 ]]; then
    printf '\nLexiGrid installation directory\n'
    printf 'Default: %s\n' "$DEFAULT_DIR"
    printf 'Current package directory: %s\n' "$ROOT"
    read -r -p 'Enter installation directory [press Enter for default]: ' INSTALL_DIR
    INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_DIR}"
  else
    echo 'ERROR: Noninteractive install requires --install-dir /absolute/path' >&2
    exit 2
  fi
fi
case "$INSTALL_DIR" in
  '~') INSTALL_DIR="$HOME";;
  '~/'*) INSTALL_DIR="$HOME/${INSTALL_DIR#~/}";;
esac
[[ "$INSTALL_DIR" == /* ]] || { echo 'ERROR: Installation directory must be an absolute path' >&2; exit 2; }
DEST="$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$INSTALL_DIR")"
if [[ "$DEST" != "$ROOT" && -d "$DEST" && -f "$DEST/VERSION" && "$UPDATE_EXISTING" -eq 0 && -t 0 ]]; then
  read -r -p 'Existing LexiGrid installation found. Type UPDATE to preserve data/config and replace application files: ' answer
  if [[ "$answer" == UPDATE ]]; then UPDATE_EXISTING=1; fi
fi
STAGE_ARGS=(--source "$ROOT" --destination "$DEST")
if [[ "$UPDATE_EXISTING" -eq 1 ]]; then STAGE_ARGS+=(--update-existing); fi
python3 "$ROOT/scripts/install_location.py" "${STAGE_ARGS[@]}"
echo "Installation location: $DEST"
# Avoid Bash 3.2 empty-array expansion under nounset.
if [[ ${#PASS_ARGS[@]} -gt 0 ]]; then
  "$DEST/scripts/install.sh" "${PASS_ARGS[@]}"
else
  "$DEST/scripts/install.sh"
fi

# Record the successful destination in the extracted package so its CLI can
# direct users to the installed copy instead of the staging directory.
if [[ "$DEST" != "$ROOT" ]]; then
  printf '%s\n' "$DEST" > "$ROOT/.lexigrid-install-target"
fi
printf '\nLexiGrid installed at: %s\n' "$DEST"
printf 'Start using: cd %q && ./lexictl start\n' "$DEST"
printf 'Or run: %q start\n' "$DEST/lexictl"
