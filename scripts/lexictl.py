#!/usr/bin/env python3
"""LexiGrid administrative CLI. Shahryar Jahangir, Aniza Inc."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.database_identity import validate_database_identity
VENV_PY = ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def runtime_environment():
    env=os.environ.copy()
    env.pop('LEXIGRID_ADMIN_DATABASE_URL',None)
    return env


def config_env():
    env = runtime_environment()
    config = ROOT / '.env.native'
    if config.exists():
        for line in config.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env[key.strip()] = value.strip()
    env.pop('LEXIGRID_ADMIN_DATABASE_URL',None)
    return env


def maintenance_env():
    """Explicit operator-only target; never persist owner credentials in runtime config."""
    env=config_env()
    if 'LEXIGRID_ADMIN_DATABASE_URL' in os.environ:
        override=os.environ['LEXIGRID_ADMIN_DATABASE_URL'].strip()
        if not override:
            raise ValueError('LEXIGRID_ADMIN_DATABASE_URL is empty; no maintenance operation was started')
        env['DATABASE_URL']=override
    env.pop('LEXIGRID_ADMIN_DATABASE_URL',None)
    validate_database_identity(env.get('DATABASE_URL',''))
    return env


def main(argv=None):
    p = argparse.ArgumentParser(prog='lexictl', description='LexiGrid operations and privileged administration')
    p.add_argument('--version', action='version', version='LexiGrid ' + (ROOT/'VERSION').read_text().strip())
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('install', 'start', 'stop', 'status', 'uninstall'):
        sub.add_parser(name, help=f'{name.capitalize()} the native service')
    sub.add_parser('health', help='Check native API health')
    sub.add_parser('logs', help='Show recent native API log entries').add_argument('--lines', type=int, default=60)
    sub.add_parser('db-upgrade', help='Apply database migrations')
    sub.add_parser('db-current', help='Show current database migration')
    sub.add_parser('db-history', help='Show migration history')
    ai = sub.add_parser('ai', help='AI provider operations')
    ai_sub = ai.add_subparsers(dest='ai_action', required=True)
    for action in ('status','providers','models','test','configure'):
        ai_sub.add_parser(action)
    admin = sub.add_parser('admin', help='Privileged user and identity operations')
    a = admin.add_subparsers(dest='action', required=True)
    for action in ('create-tenant', 'reset-password', 'bind-oidc', 'bind-saml'):
        s = a.add_parser(action)
        if action == 'create-tenant':
            s.add_argument('--name', required=True)
            s.add_argument('--role',choices=['tenant_admin','platform_admin'],default='tenant_admin')
        else:
            s.add_argument('--tenant-id', required=True)
        s.add_argument('--email', required=True)
        if action == 'bind-oidc':
            s.add_argument('--issuer', required=True)
            s.add_argument('--subject', required=True)
        if action == 'bind-saml':
            s.add_argument('--subject', required=True)
    args = p.parse_args(argv)
    if args.command == 'ai':
        if args.ai_action == 'providers':
            print('ollama (local), openai, azure_openai, anthropic')
            return 0
        if args.ai_action == 'configure':
            print('Edit .env.native in the installed LexiGrid directory; set LEXIGRID_AI_PROVIDER, MODEL, ENDPOINT, AIRGAPPED, ALLOW_CLOUD. Restart the service. Never place keys on the command line.')
            return 0
        env = config_env()
        code = ("from app.ai_risk import settings; import json, httpx; "
                "c=settings(); print(json.dumps({k:v for k,v in c.items() if k!='endpoint'})); "
                "print('Provider reachable:', httpx.get(c['endpoint'] + ('/api/tags' if c['provider']=='ollama' else '/'), timeout=5, follow_redirects=False, trust_env=False).status_code)"
                if args.ai_action == 'test' else
                "from app.ai_risk import settings; import json; print(json.dumps(settings()))")
        if args.ai_action == 'models':
            code = "from app.ai_risk import settings; import httpx; c=settings(); assert c['provider']=='ollama', 'Model listing requires Ollama'; r=httpx.get(c['endpoint']+'/api/tags',timeout=5,trust_env=False); r.raise_for_status(); print('\\n'.join(m['name'] for m in r.json()['models']))"
        return subprocess.call([str(VENV_PY if VENV_PY.exists() else sys.executable), '-c', code], cwd=ROOT, env=env)
    if args.command == 'logs':
        path = ROOT / 'run' / 'native.log'
        if not path.exists():
            p.error(f'No native log at {path}')
        with path.open(errors='replace') as f:
            from collections import deque
            for line in deque(f, maxlen=max(1, min(args.lines, 10000))):
                print(line, end='')
        return 0
    if args.command == 'health':
        args.command = 'status'
    if args.command == 'uninstall':
        return subprocess.call(['bash', str(ROOT/'uninstall.sh')], cwd=ROOT,env=runtime_environment())
    if args.command in ('install', 'start', 'stop', 'status'):
        cmd = [sys.executable, str(ROOT/'scripts/native/manager.py'), args.command]
        return subprocess.call(cmd, cwd=ROOT,env=runtime_environment())
    if not VENV_PY.exists():
        p.error('LexiGrid virtual environment missing; run lexictl install or ./install.sh')
    try:
        env = maintenance_env()
    except (ValueError,RuntimeError) as exc:
        p.error(str(exc))
    if not env.get('DATABASE_URL','').strip():
        p.error('Database not configured; install LexiGrid first')
    if args.command.startswith('db-'):
        op = {'db-upgrade':['upgrade','head'], 'db-current':['current'], 'db-history':['history']}[args.command]
        return subprocess.call([str(VENV_PY), '-m', 'alembic', *op], cwd=ROOT, env=env)
    env['LEXIGRID_ADMIN_CONFIRM'] = 'YES'
    cmd = [str(VENV_PY), '-m', 'app.admin_cli', args.action]
    for key in ('name','tenant_id','email','issuer','subject','role'):
        val = getattr(args, key, None)
        if val is not None:
            cmd += ['--'+key.replace('_','-'), val]
    return subprocess.call(cmd, cwd=ROOT, env=env)

if __name__ == '__main__':
    sys.exit(main())
