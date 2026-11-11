#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${DATABASE_URL:?DATABASE_URL is required}"
: "${RESTORE_CONFIRM:?Set RESTORE_CONFIRM=RESTORE_LEXIGRID to authorize destructive restore}"
[[ "$RESTORE_CONFIRM" == RESTORE_LEXIGRID ]] || { echo 'Restore not authorized' >&2; exit 2; }
[[ $# == 1 && -f "$1" && -f "$1.sha256" ]] || { echo 'Provide backup with SHA256 manifest' >&2; exit 2; }
# Legacy manifests may contain an absolute path. Always hash the supplied archive.
read -r expected _ < "$1.sha256"
if command -v sha256sum >/dev/null 2>&1; then
    checksum=$(sha256sum < "$1")
else
    checksum=$(shasum -a 256 < "$1")
fi
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ || "${checksum%% *}" != "$expected" ]]; then
    echo 'Backup checksum verification failed' >&2
    exit 2
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
grants="$script_dir/restore_runtime_grants.sql"
[[ -r "$grants" ]] || { echo 'Restore grant policy is missing' >&2; exit 2; }
# Send COMMIT only if both the archive renderer and grant policy were read.
# On any SQL error, psql exits and PostgreSQL rolls back the whole restore.
(
    printf 'BEGIN;\n'
    pg_restore --file=- --clean --if-exists --no-owner --no-acl -- "$1" || exit
    cat -- "$grants" || exit
    printf '\nCOMMIT;\n'
) | psql --dbname="$DATABASE_URL" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet
printf 'Restore and runtime grants completed. Run integrity verification before serving traffic.\n'
