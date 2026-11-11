"""Centralized mail configuration and operator-safe diagnostics.
Author: Shahryar Jahangir, Aniza Inc.
"""
import os, re, ssl, smtplib, json, secrets, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Column, Integer, Text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
from .main import Base, SessionLocal
from dataclasses import dataclass
from fastapi import HTTPException

@dataclass(frozen=True)
class MailConfig:
    host: str
    port: int
    security: str
    sender: str
    username: str
    password: str
    worker_enabled: bool
    webhook_enabled: bool


class MailRuntimeSettings(Base):
    __tablename__='mail_runtime_settings'
    id=Column(Integer,primary_key=True)
    encrypted_payload=Column(Text,nullable=False)
    revision=Column(Integer,nullable=False,default=1)

EDITABLE_KEYS=('LEXIGRID_SMTP_HOST','LEXIGRID_SMTP_PORT','LEXIGRID_SMTP_SECURITY','LEXIGRID_SMTP_FROM','LEXIGRID_SMTP_USERNAME','LEXIGRID_SMTP_PASSWORD')

def _mail_key():
    # Dedicated, stable 256-bit key; never regenerate on restart.
    raw=os.environ.get('LEXIGRID_MAIL_CONFIG_KEY','').strip()
    try: key=base64.urlsafe_b64decode(raw+'='*(-len(raw)%4))
    except Exception: raise RuntimeError('Invalid LEXIGRID_MAIL_CONFIG_KEY')
    if len(key)!=32:raise RuntimeError('LEXIGRID_MAIL_CONFIG_KEY must encode exactly 32 bytes')
    return key

def _encrypt(payload):
    nonce=secrets.token_bytes(12)
    return base64.urlsafe_b64encode(nonce+AESGCM(_mail_key()).encrypt(nonce,json.dumps(payload).encode(),b'lexigrid-mail-settings-v1')).decode()

def _decrypt(blob):
    raw=base64.urlsafe_b64decode(blob)
    return json.loads(AESGCM(_mail_key()).decrypt(raw[:12],raw[12:],b'lexigrid-mail-settings-v1'))

def runtime_settings():
    try:
        with SessionLocal() as s:
            row=s.get(MailRuntimeSettings,1)
            return (_decrypt(row.encrypted_payload),row.revision) if row else ({},0)
    except OperationalError as exc:
        # Older databases must be migrated before browser edits are available.
        if 'no such table: mail_runtime_settings' in str(exc):return {},0
        raise

def save_runtime_settings(s: Session, values, expected_revision):
    row = s.get(MailRuntimeSettings, 1)
    revision = row.revision if row else 0
    conflict = 'Mail configuration changed; refresh before saving'
    if revision != expected_revision:
        raise ValueError(conflict)

    existing = _decrypt(row.encrypted_payload) if row else {}
    existing.update(values)
    _, issues = load_mail_config({**os.environ, **existing}, use_runtime=False)
    if issues:
        raise ValueError('; '.join(issues))

    encrypted = _encrypt(existing)
    if row:
        statement = update(MailRuntimeSettings).where(
            MailRuntimeSettings.id == 1, MailRuntimeSettings.revision == revision,
        ).values(encrypted_payload=encrypted, revision=revision + 1)
    else:
        insert = pg_insert if s.bind.dialect.name == 'postgresql' else sqlite_insert
        statement = insert(MailRuntimeSettings).values(
            id=1, encrypted_payload=encrypted, revision=1,
        ).on_conflict_do_nothing(index_elements=[MailRuntimeSettings.id])
    if s.scalar(statement.returning(MailRuntimeSettings.id)) is None:
        raise ValueError(conflict)
    return revision + 1


def load_mail_config(environ=None, *, use_runtime=True):
    e = dict(os.environ if environ is None else environ)
    if use_runtime:
        overrides,_=runtime_settings()
        e.update(overrides)
    issues=[]
    host=e.get('LEXIGRID_SMTP_HOST','').strip()
    sender=e.get('LEXIGRID_SMTP_FROM','').strip()
    security=e.get('LEXIGRID_SMTP_SECURITY','starttls').strip().lower()
    port_raw=e.get('LEXIGRID_SMTP_PORT','587').strip()
    try:
        port=int(port_raw)
        if not 1<=port<=65535: raise ValueError()
    except ValueError:
        port=0; issues.append('SMTP port must be an integer between 1 and 65535')
    if security not in ('starttls','ssl'):
        issues.append('SMTP security must be starttls or ssl')
    if host and (len(host)>253 or not re.fullmatch(r'[a-zA-Z0-9.\-:\[\]]+',host)):
        issues.append('SMTP host contains invalid characters')
    if sender and (len(sender)>320 or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+',sender)):
        issues.append('SMTP sender must be a valid email address')
    user=e.get('LEXIGRID_SMTP_USERNAME','').strip()
    password=e.get('LEXIGRID_SMTP_PASSWORD','')
    if user and not password: issues.append('SMTP password is required when SMTP username is set')
    if password and not user: issues.append('SMTP username is required when SMTP password is set')
    worker=e.get('LEXIGRID_MAIL_WORKER','0').strip()
    if worker not in ('0','1'): issues.append('Mail worker must be 0 or 1')
    enabled=worker=='1'
    if enabled and not host: issues.append('SMTP host is required when mail worker is enabled')
    if enabled and not sender: issues.append('SMTP sender is required when mail worker is enabled')
    webhook=e.get('LEXIGRID_MAIL_WEBHOOK_SECRET','')
    if webhook and len(webhook)<32: issues.append('Webhook signing secret must be at least 32 characters')
    cfg=MailConfig(host,port,security,sender,user,password,enabled,bool(webhook))
    return cfg,issues


def require_smtp():
    cfg,issues=load_mail_config()
    if not cfg.host: issues.append('SMTP host is not configured')
    if not cfg.sender: issues.append('SMTP sender is not configured')
    if issues: raise HTTPException(503,'Email configuration invalid: '+ '; '.join(dict.fromkeys(issues)))
    return cfg


def public_status():
    cfg,issues=load_mail_config()
    _,revision=runtime_settings()
    return {'revision':revision,'smtp_host':cfg.host,'smtp_port':cfg.port,'smtp_security':cfg.security,
            'smtp_from':cfg.sender,'smtp_username':cfg.username,'smtp_username_configured':bool(cfg.username),
            'smtp_password_configured':bool(cfg.password),'mail_worker_enabled':cfg.worker_enabled,
            'webhook_secret_configured':cfg.webhook_enabled,
            'smtp_ready':bool(cfg.host and cfg.sender and not issues),'validation_errors':issues,
            'configuration_source':'encrypted database overrides with environment fallback; browser changes take effect on next send without restart',
            'credentials_exposed':False}


def probe_smtp():
    cfg=require_smtp()
    ctx=ssl.create_default_context()
    client=smtplib.SMTP_SSL(cfg.host,cfg.port,timeout=10,context=ctx) if cfg.security=='ssl' else smtplib.SMTP(cfg.host,cfg.port,timeout=10)
    with client as smtp:
        if cfg.security=='starttls': smtp.starttls(context=ctx)
        if cfg.username: smtp.login(cfg.username,cfg.password)
        smtp.noop()
    return {'connection':'successful','authentication':'successful' if cfg.username else 'not_configured',
            'message_sent':False}
