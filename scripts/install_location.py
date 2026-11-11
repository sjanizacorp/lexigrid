#!/usr/bin/env python3
"""Safe, repeatable LexiGrid install-directory staging."""
from pathlib import Path
import argparse
import shutil
import sys

EXCLUDE = {'.venv', '.git', '__pycache__', '.pytest_cache', 'run', 'data', 'logs', 'node_modules', 'dist', 'build'}
PRESERVE = {'.env', '.env.native', '.lexigrid-deployment-mode', 'config/logging.json'}

def stage(source: Path, destination: Path, update: bool = False) -> None:
    source = source.resolve()
    destination = destination.expanduser().resolve()
    if source == destination:
        print(f'Installing in existing directory: {source}', flush=True)
        return
    if source in destination.parents or destination in source.parents:
        raise ValueError('Install destination must not be nested inside the source (or vice versa).')
    if destination.exists() and any(destination.iterdir()):
        if not (destination / 'VERSION').exists():
            raise ValueError('Destination is nonempty and is not an existing LexiGrid installation.')
        if not update:
            raise ValueError('Existing LexiGrid installation: use --update-existing to update application files while preserving configuration and data.')
    destination.mkdir(parents=True, exist_ok=True)
    for p in source.rglob('*'):
        rel = p.relative_to(source)
        if any(part in EXCLUDE for part in rel.parts) or p.is_symlink():
            continue
        target = destination / rel
        if p.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif p.is_file():
            if rel.as_posix() in PRESERVE and target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
    print(f'Application files staged in: {destination}', flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=Path, required=True)
    ap.add_argument('--destination', type=Path, required=True)
    ap.add_argument('--update-existing', action='store_true')
    a=ap.parse_args()
    try:
        stage(a.source,a.destination,a.update_existing)
    except (ValueError,OSError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    return 0
if __name__ == '__main__':
    sys.exit(main())
