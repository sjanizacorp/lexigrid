"""Configuration-driven operational and security event logging for LexiGrid.
Author: Shahryar Jahangir, Aniza Inc.
"""
from contextvars import ContextVar
import json
import logging
import logging.handlers
import os
import re
import socket
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

REQUEST_CONTEXT = ContextVar("lexigrid_request_context", default={})

_LOCK = threading.Lock()
_INITIALIZED = False
_LOGGERS = {}
_SECRET = re.compile(r"(?i)(password|secret|token|api.?key|authorization|cookie|credential|private.?key)")

class JSONFormatter(logging.Formatter):
    def format(self, record):
        event = getattr(record, 'event', {})
        return json.dumps({'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                           'level': record.levelname, 'logger': record.name,
                           'event': redact(event), 'message': record.getMessage()},
                          sort_keys=True, default=str, ensure_ascii=False)

def redact(value):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if _SECRET.search(str(k)) else redact(v) for k,v in value.items()}
    if isinstance(value, list): return [redact(x) for x in value]
    if isinstance(value, str): return value[:2048]
    return value

def load_settings():
    path = Path(os.environ.get('LEXIGRID_LOG_CONFIG', 'config/logging.json')).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f'Missing logging configuration: {path}')
    cfg = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(cfg, dict): raise ValueError('Logging configuration must be an object')
    if cfg.get('version') != 1: raise ValueError('Unsupported logging configuration version')
    for key in ('system', 'operations'):
        if not isinstance(cfg.get(key), dict): raise ValueError(f'Missing logging section: {key}')
        if cfg[key].get('level', 'INFO') not in ('DEBUG','INFO','WARNING','ERROR','CRITICAL'):
            raise ValueError(f'Invalid logging level: {key}')
    return cfg, path

def _file_handler(filename, max_bytes, backups, base):
    dest = (base / filename).resolve()
    if not dest.is_relative_to(base.resolve()): raise ValueError('Log path escapes configured directory')
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(dest, maxBytes=max_bytes, backupCount=backups, encoding='utf-8')
    h.setFormatter(JSONFormatter())
    return h

def _remote_handler(cfg):
    if not cfg.get('enabled', False): return None
    kind = cfg.get('type', 'syslog_udp')
    host = cfg.get('host')
    port = cfg.get('port')
    if not isinstance(host,str) or not host or not isinstance(port,int) or not 1 <= port <= 65535:
        raise ValueError('Central logging requires valid host and port')
    if kind in ('syslog_udp', 'syslog_tcp'):
        socktype = socket.SOCK_DGRAM if kind == 'syslog_udp' else socket.SOCK_STREAM
        handler = logging.handlers.SysLogHandler(address=(host,port), socktype=socktype, facility=logging.handlers.SysLogHandler.LOG_LOCAL0)
    elif kind == 'syslog_tls':
        handler = TLSSyslogHandler(host, port, cfg.get('ca_file'))
    else:
        raise ValueError('Unsupported central logging type (syslog_udp, syslog_tcp, syslog_tls)')
    handler.setFormatter(JSONFormatter())
    return handler

class TLSSyslogHandler(logging.Handler):
    def __init__(self, host, port, ca_file):
        super().__init__()
        if not ca_file: raise ValueError('syslog_tls requires ca_file for certificate validation')
        self.host, self.port = host, port
        self.context = ssl.create_default_context(cafile=ca_file)
    def emit(self, record):
        try:
            payload = ('<134>1 ' + datetime.now(timezone.utc).isoformat() + ' lexigrid app - - - ' + self.format(record) + '\n').encode('utf-8')
            with socket.create_connection((self.host, self.port), timeout=2) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.host) as conn: conn.sendall(payload)
        except Exception:
            self.handleError(record)

def configure():
    global _INITIALIZED
    with _LOCK:
        if _INITIALIZED: return
        cfg, config_path = load_settings()
        base = (config_path.parent.parent / cfg.get('directory', 'logs')).resolve()
        base.mkdir(parents=True, exist_ok=True)
        max_bytes = cfg.get('max_bytes', 10485760)
        backups = cfg.get('backup_count', 10)
        if not isinstance(max_bytes,int) or not 1024 <= max_bytes <= 1073741824: raise ValueError('Invalid max_bytes')
        if not isinstance(backups,int) or not 1 <= backups <= 100: raise ValueError('Invalid backup_count')
        handlers = []
        try:
            for key in ('system','operations'):
                entry = cfg[key]
                logger = logging.getLogger('lexigrid.' + key)
                logger.setLevel(entry.get('level', 'INFO'))
                logger.propagate = False
                handler = _file_handler(entry.get('file', key+'.jsonl'), max_bytes, backups, base)
                handlers.append(handler)
                logger.addHandler(handler)
                remote = _remote_handler(cfg.get('central', {}))
                if remote:
                    handlers.append(remote)
                    logger.addHandler(remote)
                _LOGGERS[key] = logger
            _INITIALIZED = True
        except Exception:
            for logger in _LOGGERS.values():
                for h in list(logger.handlers): logger.removeHandler(h)
            for h in handlers: h.close()
            _LOGGERS.clear()
            raise

def emit(channel, action, **details):
    configure()
    logger = _LOGGERS[channel]
    level = logging.ERROR if details.get('outcome') == 'error' else logging.INFO
    logger.log(level, action, extra={'event': {**REQUEST_CONTEXT.get(), 'action':action, **details}})
