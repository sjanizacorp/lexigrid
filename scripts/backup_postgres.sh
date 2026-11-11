#!/usr/bin/env bash
# LexiGrid database backup: output is NOT encrypted; protect immediately.
set -euo pipefail
umask 077
: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_DIR:?BACKUP_DIR is required}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python="$root/.venv/bin/python"
if [[ ! -x "$python" ]]; then python=python3; fi
"$python" "$root/app/database_identity.py"
mkdir -p "$BACKUP_DIR"
stage=$(mktemp -d "$BACKUP_DIR/.lexigrid-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
name="${stage##*/}"
name="${name#.}.dump"
trap 'rm -f -- "$stage/$name" "$stage/$name.sha256"; rmdir -- "$stage"' EXIT
pg_dump --dbname="$DATABASE_URL" --format=custom --no-owner --no-acl --file="$stage/$name"
if command -v sha256sum >/dev/null 2>&1; then
    checksum=$(sha256sum < "$stage/$name")
else
    checksum=$(shasum -a 256 < "$stage/$name")
fi
printf '%s  %s\n' "${checksum%% *}" "$name" > "$stage/$name.sha256"
mv -- "$stage/$name" "$BACKUP_DIR/$name"
mv -- "$stage/$name.sha256" "$BACKUP_DIR/$name.sha256"
printf 'Backup created: %s\n' "$BACKUP_DIR/$name"
printf 'WARNING: backup contains sensitive data. Encrypt and transfer it to protected offline storage.\n'
