#!/usr/bin/env python3
"""Remove a LexiGrid installation after service shutdown; preserve data by default."""
import argparse
import datetime
import os
from pathlib import Path
import shutil
import sys

PRESERVE = ('.env', '.env.native', 'config', 'logs', 'run', 'data', 'backups', 'uploads', 'evidence', 'storage', 'certs', 'secrets')

def clean(root: Path, *, yes=False, delete_data=False, backup_dir=None):
    root = root.absolute()
    if root.is_symlink() or not root.is_dir() or not (root/'VERSION').is_file() or not (root/'scripts'/'native'/'manager.py').is_file():
        raise ValueError('Refusing to remove a path that is not a verified LexiGrid installation')
    if root == Path.home() or root == Path('/') or len(root.parts) < 3:
        raise ValueError('Refusing unsafe installation directory')
    if delete_data and not yes:
        raise ValueError('Deleting data requires explicit --yes and --delete-data')
    if not yes:
        response = input(f'Remove LexiGrid application at {root}? Type UNINSTALL: ')
        if response != 'UNINSTALL':
            print('Cancelled; no files removed')
            return False
    destination = None
    if not delete_data:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        destination = Path(backup_dir).expanduser().absolute() if backup_dir else root.parent / f'{root.name}-preserved-{timestamp}'
        if destination == root or root in destination.parents or destination in root.parents:
            raise ValueError('Preservation destination must be outside the installation tree')
        if destination.exists():
            raise FileExistsError(f'Preservation destination already exists: {destination}')
        destination.mkdir(parents=True, mode=0o700)
        try:
            for name in PRESERVE:
                source = root/name
                if source.is_symlink():
                    raise ValueError(f'Refusing to follow symlink in preserved data: {source}')
                if source.exists():
                    shutil.copytree(source, destination/name, symlinks=True) if source.is_dir() else shutil.copy2(source, destination/name)
            # SQLite files can live in the application root; preserve them too.
            for pattern in ('*.db', '*.sqlite', '*.sqlite3', '*.db-wal', '*.db-shm'):
                for source in root.glob(pattern):
                    if source.is_file() and not source.is_symlink():
                        shutil.copy2(source, destination/source.name)
        except Exception:
            print(f'Preservation failed; installation left intact. Check {destination}', file=sys.stderr)
            raise
    shutil.rmtree(root)
    print(f'Removed installation: {root}')
    if destination:
        print(f'Preserved configuration, logs and local data at: {destination}')
        print('External PostgreSQL databases and Docker volumes are not deleted by this cleanup.')
    else:
        print('Local installation files and local data deleted. External databases and Docker volumes require separate removal.')
    return True

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--delete-data', action='store_true')
    parser.add_argument('--backup-dir')
    args=parser.parse_args()
    try:
        clean(args.root, yes=args.yes, delete_data=args.delete_data, backup_dir=args.backup_dir)
    except (ValueError, OSError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0
if __name__=='__main__':
    sys.exit(main())
