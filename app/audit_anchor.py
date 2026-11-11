"""Portable, independently verifiable audit checkpoints.

Copyright (c) Aniza Inc. Author: Shahryar Jahangir.
Checkpoints must be copied to independently controlled, append-only storage.
"""
import argparse
import hashlib
import hmac
import json
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import select, text


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def record_payload(record):
    timestamp = record.at
    return {
        'id': record.id, 'tenant_id': record.tenant_id,
        'at': timestamp.replace(tzinfo=None).isoformat(),
        'actor_id': record.actor_id, 'action': record.action,
        'object_id': record.object_id, 'details': record.details,
        'integrity_mac': record.integrity_mac,
    }


def build_checkpoint(records, signing_key, previous_digest=None, generated_at=None):
    if not signing_key or len(signing_key) < 48:
        raise ValueError('A separate checkpoint signing key of at least 48 characters is required')
    rows = sorted((record_payload(r) for r in records), key=lambda r: (r['at'], r['id']))
    chain = '0' * 64
    for row in rows:
        chain = hashlib.sha256(bytes.fromhex(chain) + canonical(row)).hexdigest()
    body = {
        'format': 'lexigrid-audit-checkpoint-v1',
        'generated_at': generated_at or datetime.now(timezone.utc).isoformat(),
        'record_count': len(rows),
        'first_record_id': rows[0]['id'] if rows else None,
        'last_record_id': rows[-1]['id'] if rows else None,
        'records_sha256': chain,
        'previous_checkpoint_sha256': previous_digest,
    }
    signature = hmac.new(signing_key.encode(), canonical(body), hashlib.sha256).hexdigest()
    return {**body, 'signature_hmac_sha256': signature}


def verify_checkpoint(checkpoint, records, signing_key):
    body = {k: v for k, v in checkpoint.items() if k != 'signature_hmac_sha256'}
    expected = hmac.new(signing_key.encode(), canonical(body), hashlib.sha256).hexdigest()
    signature = checkpoint.get('signature_hmac_sha256', '')
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        return False
    rebuilt = build_checkpoint(records, signing_key,
                               previous_digest=body.get('previous_checkpoint_sha256'),
                               generated_at=body.get('generated_at'))
    return hmac.compare_digest(canonical(rebuilt), canonical(checkpoint))


def checkpoint_digest(checkpoint):
    return hashlib.sha256(canonical(checkpoint)).hexdigest()


def atomic_write_new(path, checkpoint):
    """Create without overwrite. Caller must place result in external WORM storage."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as out:
        out.write(json.dumps(checkpoint, indent=2, sort_keys=True) + '\n')
    return path


def load_audit_records(session, tenant_id=None):
    from .main import Audit, Tenant
    if tenant_id is not None:
        tenant_id = str(uuid.UUID(tenant_id))
        if session.get(Tenant, tenant_id) is None:
            raise ValueError('Audit tenant was not found')
        if session.bind.dialect.name == 'postgresql':
            session.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"),
                            {'tenant':tenant_id})
    elif session.bind.dialect.name == 'postgresql':
        privileged = session.scalar(text("""
            SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user
        """))
        if not privileged:
            raise ValueError('Specify --tenant-id when checkpointing with a role subject to tenant isolation')
    query = select(Audit)
    if tenant_id is not None:
        query = query.where(Audit.tenant_id == tenant_id)
    return session.scalars(query.order_by(Audit.at, Audit.id)).all()


def main():
    parser = argparse.ArgumentParser(description='Create or verify a LexiGrid audit checkpoint')
    parser.add_argument('action', choices=['create', 'verify'])
    parser.add_argument('--output', required=True, help='Checkpoint file path')
    parser.add_argument('--previous', help='Prior checkpoint file (create only)')
    parser.add_argument('--tenant-id', help='Tenant to checkpoint with a restricted database role')
    args = parser.parse_args()
    key = os.environ.get('LEXIGRID_ANCHOR_HMAC_KEY', '')
    if len(key) < 48:
        parser.error('LEXIGRID_ANCHOR_HMAC_KEY must be at least 48 characters')
    from .main import SessionLocal
    with SessionLocal() as session:
        try:
            records = load_audit_records(session, args.tenant_id)
        except ValueError as exc:
            parser.error(str(exc))
    if args.action == 'create':
        previous = checkpoint_digest(json.loads(Path(args.previous).read_text())) if args.previous else None
        cp = build_checkpoint(records, key, previous_digest=previous)
        atomic_write_new(args.output, cp)
        print(f'Created checkpoint for {len(records)} records: {args.output}')
    else:
        cp = json.loads(Path(args.output).read_text())
        if not verify_checkpoint(cp, records, key):
            raise SystemExit('Audit checkpoint verification FAILED')
        print('Audit checkpoint verification PASSED')


if __name__ == '__main__':
    main()
