"""Cross-platform native service lifecycle, Windows/macOS/Linux.
Author: Shahryar Jahangir / Aniza Inc.
Native mode requires an independently provisioned PostgreSQL database for production.
"""
import argparse
import getpass
from http.client import HTTPException as HTTPClientError
from urllib.parse import quote
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
import urllib.request
import venv

ROOT = Path(__file__).resolve().parents[2]
# Keep this launcher usable without SQLAlchemy in its own interpreter.
sys.path.insert(0,str(ROOT))
from app.database_identity import validate_database_identity
STATE = ROOT / 'run'
VENV = ROOT / '.venv'
CONFIG = ROOT / '.env.native'

def python_bin():
    return VENV / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')

def read_config():
    if not CONFIG.exists():
        raise RuntimeError('Missing .env.native; run install first')
    result = {}
    for line in CONFIG.read_text().splitlines():
        if line and not line.startswith('#') and '=' in line:
            k,v = line.split('=',1)
            result[k]=v
    return result

def select_database(args):
    """Select an existing local PostgreSQL service or an on-disk SQLite database.

    PostgreSQL must already be installed and listening; we never install or
    silently reconfigure the database server.
    """
    if args.database_url:
        return validate_database_identity(args.database_url)
    kind=args.database
    if not kind:
        if not sys.stdin.isatty():
            raise RuntimeError('Noninteractive install requires --database sqlite|postgres or --database-url')
        print('Select native database:')
        print('  1) Local PostgreSQL (recommended for production; must be installed and running)')
        print('  2) SQLite file (development and single-user evaluation only)')
        choice=input('Choose 1 or 2: ').strip()
        kind={'1':'postgres','2':'sqlite'}.get(choice)
        if not kind:
            raise RuntimeError('Invalid database selection')
    if kind=='sqlite':
        # Use an absolute path so migrations and runtime access the same file.
        path=(ROOT/'data'/'lexigrid.sqlite3').resolve()
        path.parent.mkdir(parents=True,exist_ok=True)
        return 'sqlite:///'+path.as_posix()
    if kind!='postgres':
        raise RuntimeError('Database must be sqlite or postgres')
    host=args.pg_host or '127.0.0.1'
    port=args.pg_port
    db=args.pg_database or 'lexigrid'
    user=args.pg_user or 'lexigrid_owner'
    password=args.pg_password
    if password is None:
        if not sys.stdin.isatty():
            raise RuntimeError('Provide --pg-password or --database-url for unattended PostgreSQL installation')
        password=getpass.getpass('Local PostgreSQL password: ')
    if not password:
        raise RuntimeError('PostgreSQL password cannot be empty')
    return validate_database_identity(f'postgresql+psycopg://{quote(user,safe="")}:{quote(password,safe="")}@{host}:{port}/{quote(db,safe="")}')


def verify_database(url):
    """Probe using the installed virtual environment, never the launcher Python.

    The launcher is normally macOS /usr/bin/python3 or Homebrew Python, while
    SQLAlchemy and database drivers are installed into .venv. Importing them in
    the launcher causes ModuleNotFoundError even after successful pip install.
    """
    validate_database_identity(url)
    probe = (
        'import os\n'
        'from sqlalchemy import create_engine, text\n'
        'url = os.environ["LEXIGRID_DATABASE_PROBE_URL"]\n'
        'engine = create_engine(url, pool_pre_ping=True, '
        'connect_args={"connect_timeout": 5} if url.startswith("postgresql") else {})\n'
        'try:\n'
        '    with engine.connect() as conn:\n'
        '        conn.execute(text("SELECT 1"))\n'
        'finally:\n'
        '    engine.dispose()\n'
    )
    env = os.environ.copy()
    env['LEXIGRID_DATABASE_PROBE_URL'] = url
    result = subprocess.run([str(python_bin()), '-c', probe], cwd=ROOT,
                            env=env, text=True, capture_output=True)
    if result.returncode:
        # Do not print exception text: PostgreSQL driver errors may include
        # credentials or sensitive connection details.
        raise RuntimeError(
            'Database verification failed using the LexiGrid virtual environment. '
            'For SQLite, check directory permissions. For PostgreSQL, check server '
            'availability, database/user creation and credentials. '
            'See the error output from a local diagnostic run for details.'
        )

def install(args):
    if sys.version_info < (3,11):
        raise RuntimeError('Python 3.11+ required')
    if not VENV.exists():
        venv.EnvBuilder(with_pip=True).create(VENV)
    subprocess.run([str(python_bin()),'-m','pip','install','-r',str(ROOT/'requirements.txt')],check=True)
    # Validate critical imports in the same interpreter that runs the application.
    subprocess.run([str(python_bin()), '-c', 'import sqlalchemy, alembic, fastapi, uvicorn'], check=True)
    if not CONFIG.exists():
        url=select_database(args)
        # Fail before saving configuration when the local DB cannot be reached.
        verify_database(url)
        env={k:secrets.token_hex(32) for k in ('JWT_SECRET','AUDIT_HMAC_KEY','EVIDENCE_ENCRYPTION_KEY','LEXIGRID_MFA_ENCRYPTION_KEY','LEXIGRID_ANCHOR_HMAC_KEY')}
        env['LEXIGRID_MFA_ENCRYPTION_KEY']=__import__('base64').urlsafe_b64encode(secrets.token_bytes(32)).decode()
        env['LEXIGRID_MAIL_CONFIG_KEY']=__import__('base64').urlsafe_b64encode(secrets.token_bytes(32)).decode()
        env['DATABASE_URL']=url
        env['LEXIGRID_DEV_BOOTSTRAP']='0'
        env['LEXIGRID_REQUIRE_MFA']='1'
        env['LEXIGRID_REQUIRE_LOCAL_MFA']='0'
        try:
            fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise RuntimeError('Native configuration was created by another process. Rerun install.') from exc
        with os.fdopen(fd, 'w', encoding='utf-8') as cfg_file:
            cfg_file.write('# LexiGrid native configuration. Protect this file.\n')
            cfg_file.writelines(f'{key}={value}\n' for key, value in env.items())
    else:
        validate_database_identity(read_config().get('DATABASE_URL',''))
        if os.name != 'nt':
            CONFIG.chmod(0o600)
        if 'LEXIGRID_MAIL_CONFIG_KEY' not in read_config():
            with CONFIG.open('a') as cfg_file:
                cfg_file.write('\nLEXIGRID_MAIL_CONFIG_KEY='+__import__('base64').urlsafe_b64encode(secrets.token_bytes(32)).decode()+'\n')
            print('Added new mail encryption key without modifying existing configuration.')
        print('Existing .env.native retained; no secrets or database selection overwritten.')
        print('To switch databases, migrate/backup data first and explicitly update .env.native.')
    env=os.environ.copy();env.update(read_config())
    verify_database(env['DATABASE_URL'])
    if env['DATABASE_URL'].startswith('sqlite'):
        print('WARNING: SQLite native mode is for development only; not production or multi-worker deployments.')
    else:
        print('Connected to local PostgreSQL. Migrations require a schema-owner connection.')
    if not args.skip_migrations:
        subprocess.run([str(python_bin()),'-m','alembic','upgrade','head'],cwd=ROOT,env=env,check=True)
    # Bootstrap only a genuinely empty installation. Never reset an existing admin.
    bootstrap_initial_admin(env)
    install_cli_command()
    print(f'Installed at: {ROOT}')
    print(f'Start with: {ROOT / "lexictl"} start')
    print('Or use lexictl start if ~/.local/bin is on PATH.')
    if env['DATABASE_URL'].split(':', 1)[0].startswith('postgres'):
        print('Before starting PostgreSQL native mode, set DATABASE_URL in .env.native to the restricted lexigrid_runtime connection.')
        print('Retain schema-owner credentials separately for migrations. Native startup enforces database security checks.')

def install_cli_command():
    """Install a user-local lexictl shim without requiring root privileges."""
    if os.name == 'nt':
        print('Windows: run python scripts/lexictl.py <command>')
        return
    bindir = Path.home() / '.local' / 'bin'
    try:
        bindir.mkdir(parents=True, exist_ok=True)
        target = bindir / 'lexictl'
        # Never overwrite an unrelated executable.
        if target.exists() or target.is_symlink():
            if not target.is_symlink() or target.resolve() != ROOT / 'lexictl':
                print(f'Existing {target} left unchanged. Use {ROOT / "lexictl"}.')
                return
        else:
            target.symlink_to(ROOT / 'lexictl')
        print(f'CLI: {target} (add {bindir} to PATH if needed).')
    except OSError:
        print(f'Could not register user CLI; use {ROOT / "lexictl"}.')

def bootstrap_initial_admin(env):
    """Create a random one-time admin credential, print it once, never save plaintext."""
    probe = (
        'from sqlalchemy import create_engine, text\n'
        'import os\n'
        'e=create_engine(os.environ["DATABASE_URL"])\n'
        'with e.connect() as c:\n'
        ' print(c.execute(text("SELECT COUNT(*) FROM tenants")).scalar_one())\n'
    )
    count = subprocess.run([str(python_bin()), '-c', probe], cwd=ROOT,
                           env=env, capture_output=True, text=True, check=True).stdout.strip()
    if count != '0':
        print('Existing tenant(s) detected. No administrator password was changed.')
        return
    if not sys.stdin.isatty():
        print('No initial administrator created in unattended mode. Use ./lexictl admin create-tenant --role platform_admin with an owner maintenance connection.')
        return
    print('\nFirst-time administrator setup (empty database)')
    name = input('Organization name [LexiGrid]: ').strip() or 'LexiGrid'
    email = input('Administrator email [admin@lexigrid.local]: ').strip() or 'admin@lexigrid.local'
    if '@' not in email:
        raise RuntimeError('Administrator email must contain @')
    password = secrets.token_urlsafe(24)
    # Password passes through a child process environment, never through argv,
    # a file, the terminal command history, or application logs.
    bootstrap_env = dict(env, LEXIGRID_BOOTSTRAP_NAME=name,
                         LEXIGRID_BOOTSTRAP_EMAIL=email,
                         LEXIGRID_BOOTSTRAP_PASSWORD=password)
    code = (
        'import os\n'
        'from sqlalchemy import create_engine\n'
        'from app.admin_cli import provision_tenant\n'
        'print(provision_tenant(create_engine(os.environ["DATABASE_URL"]), '
        'os.environ["LEXIGRID_BOOTSTRAP_NAME"], '
        'os.environ["LEXIGRID_BOOTSTRAP_EMAIL"], '
        'os.environ["LEXIGRID_BOOTSTRAP_PASSWORD"],role="platform_admin"))\n'
    )
    result = subprocess.run([str(python_bin()), '-c', code], cwd=ROOT,
                            env=bootstrap_env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError('Administrator provisioning failed; use ./lexictl admin create-tenant')
    print('\n' + '=' * 64)
    print('INITIAL ADMINISTRATOR CREDENTIALS — SHOWN ONCE')
    print('Tenant ID: ' + result.stdout.strip())
    print('Username:  ' + email.lower())
    print('Password:  ' + password)
    print('ACTION REQUIRED: Sign in and change this password immediately.')
    print('The password is NOT stored in plaintext; copy it to a password manager.')
    print('You can reset it with ./lexictl admin reset-password.')
    print('=' * 64 + '\n')

def status(_args):
    pidfile = STATE / 'native.pid'
    if not pidfile.exists():
        print('Native API: STOPPED')
        return 1
    try:
        data = json.loads(pidfile.read_text())
        pid, port = data['pid'], data['port']
    except (OSError, ValueError, TypeError, KeyError):
        print('Native API: NOT HEALTHY (invalid run/native.pid)')
        return 1
    if status_quiet(port, data.get('instance'), timeout=3):
        print(f'Native API: HEALTHY pid={pid} port={port}')
        return 0
    print(f'Native API: NOT HEALTHY (recorded pid={pid}); check run/native.log')
    return 1


def start(args):
    if status(None) == 0:
        return
    env = os.environ.copy()
    env.update(read_config())
    validate_database_identity(env.get('DATABASE_URL',''))
    if env.get('DATABASE_URL', '').split(':', 1)[0].startswith('postgres'):
        env['LEXIGRID_REQUIRE_DB_SECURITY'] = '1'
    instance = secrets.token_hex(16)
    env['LEXIGRID_NATIVE_INSTANCE_ID'] = instance
    STATE.mkdir(exist_ok=True)
    cmd = [str(python_bin()), '-m', 'uvicorn', 'app.main:app', '--host', args.host,
           '--port', str(args.port)]
    with (STATE / 'native.log').open('ab', buffering=0) as log:
        options = {'cwd':str(ROOT), 'env':env, 'stdin':subprocess.DEVNULL,
                   'stdout':log, 'stderr':subprocess.STDOUT}
        if os.name == 'nt':
            options['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        else:
            options['start_new_session'] = True
        proc = subprocess.Popen(cmd, **options)

    ready = False
    try:
        for _ in range(30):
            time.sleep(.5)
            if proc.poll() is not None:
                break
            if status_quiet(args.port, instance):
                (STATE / 'native.pid').write_text(json.dumps(
                    {'pid':proc.pid, 'port':args.port, 'instance':instance}
                ))
                ready = True
                print('Started API. For production, use a TLS-terminating reverse proxy.')
                return
        raise RuntimeError('API failed to start; inspect run/native.log')
    finally:
        if not ready and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def status_quiet(port, instance=None, *, timeout=.5):
    try:
        url = f'http://127.0.0.1:{port}/health'
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                return False
            if instance is not None and response.headers.get('X-LexiGrid-Native-Instance') != instance:
                return False
            payload = json.loads(response.read(4096))
            return payload.get('status') == 'ok' and bool(payload.get('version'))
    except (OSError, ValueError, AttributeError, HTTPClientError):
        return False


def process_running(pid):
    if os.name=='nt':
        import ctypes
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.restype=ctypes.c_void_p
        kernel.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
        kernel.GetExitCodeProcess.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
        kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        handle=kernel.OpenProcess(0x1000,False,pid)
        if not handle:
            if ctypes.get_last_error()==87:return False
            raise RuntimeError('Cannot verify native process termination')
        try:
            status=ctypes.c_ulong()
            if not kernel.GetExitCodeProcess(handle,ctypes.byref(status)):
                raise RuntimeError('Cannot query native process state')
            return status.value==259
        finally:kernel.CloseHandle(handle)
    try:
        ended,_=os.waitpid(pid,os.WNOHANG)
        if ended==pid:return False
    except ChildProcessError:pass
    try:os.kill(pid,0)
    except ProcessLookupError:return False
    except PermissionError:raise RuntimeError('Cannot verify native process termination')
    return True


def wait_for_exit(pid,timeout=15):
    deadline=time.monotonic()+timeout
    while process_running(pid):
        if time.monotonic()>=deadline:
            raise RuntimeError('Native shutdown did not complete; process state retained. Inspect the process before retrying.')
        time.sleep(.1)


def stop(_args):
    state = STATE / 'native.pid'
    if not state.exists():
        print('Already stopped')
        return
    try:
        record = json.loads(state.read_text())
        pid, port = record['pid'], record['port']
        if type(pid) is not int or pid <= 1:
            raise ValueError('Invalid process ID')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise RuntimeError('Invalid native process state; inspect run/native.pid') from exc
    if not status_quiet(port, record.get('instance'), timeout=3):
        if os.name != 'nt':
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                state.unlink(missing_ok=True)
                print('Already stopped; removed stale native state')
                return
            except PermissionError:
                pass
        raise RuntimeError('Cannot verify the recorded native instance; inspect its process and run/native.log before stopping it')
    try:
        if os.name == 'nt':
            result = subprocess.run(['taskkill', '/PID', str(pid), '/T'],
                                    capture_output=True, check=False)
            if result.returncode:
                raise RuntimeError('Native process could not be stopped')
        else:
            if os.getpgid(pid) != pid:
                raise RuntimeError('Native process group does not match the recorded process')
            os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    wait_for_exit(pid)
    state.unlink(missing_ok=True)
    print('Native API stopped')


def uninstall(args):
    stop(args)
    if not args.yes:
        if input('Remove native Python environment? Type UNINSTALL: ')!='UNINSTALL':raise RuntimeError('Cancelled')
    if VENV.exists():
        import shutil;shutil.rmtree(VENV)
    print('Native virtual environment removed. Configuration, logs and database preserved.')
    if args.delete_data:
        raise RuntimeError('Database removal is deliberately not automated; back up and remove through your DB administrator.')

def main():
    p=argparse.ArgumentParser(description='LexiGrid native lifecycle (Windows/Linux/macOS)')
    sub=p.add_subparsers(dest='action',required=True)
    i=sub.add_parser('install');i.add_argument('--database-url');i.add_argument('--database',choices=['sqlite','postgres']);i.add_argument('--pg-host',default='127.0.0.1');i.add_argument('--pg-port',type=int,default=5432);i.add_argument('--pg-database',default='lexigrid');i.add_argument('--pg-user',default='lexigrid_owner');i.add_argument('--pg-password');i.add_argument('--skip-migrations',action='store_true')
    s=sub.add_parser('start');s.add_argument('--host',default='127.0.0.1');s.add_argument('--port',type=int,default=8000)
    sub.add_parser('stop');sub.add_parser('status')
    u=sub.add_parser('uninstall');u.add_argument('--yes',action='store_true');u.add_argument('--delete-data',action='store_true')
    args=p.parse_args()
    try:
        return {'install':install,'start':start,'stop':stop,'status':status,'uninstall':uninstall}[args.action](args) or 0
    except (RuntimeError,subprocess.CalledProcessError) as e:
        print('ERROR:',e,file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
