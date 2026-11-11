"""Conjur Open Source secret-backed evidence encryption.

Conjur is a secrets manager, not a cryptographic Transit/HSM service. Encryption
happens locally with AES-256-GCM; Conjur supplies versioned 32-byte keys.
Shahryar Jahangir / Aniza Inc.
"""
import base64
import json
import os
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ConjurError(RuntimeError):
    pass


class ConjurUnavailable(ConjurError):
    """Provider access/configuration failed, without proving ciphertext damage."""


def _config():
    base = os.getenv('LEXIGRID_CONJUR_URL', '').rstrip('/')
    account = os.getenv('LEXIGRID_CONJUR_ACCOUNT', '')
    if not base.startswith('https://') or not account or '/' in account:
        raise ConjurUnavailable('Conjur requires HTTPS and a valid account')
    return base, account


def _secret_key(secret_id: str) -> bytes:
    base, account = _config()
    if not secret_id or len(secret_id) > 200 or secret_id.startswith('/') or '..' in secret_id.split('/'):
        raise ConjurError('Invalid Conjur variable identifier')
    verify = os.getenv('LEXIGRID_CONJUR_CA_BUNDLE') or True
    token = os.getenv('LEXIGRID_CONJUR_AUTH_TOKEN', '')
    try:
        with httpx.Client(timeout=8, verify=verify, follow_redirects=False) as client:
            if not token:
                login = os.getenv('LEXIGRID_CONJUR_LOGIN', '')
                api_key = os.getenv('LEXIGRID_CONJUR_API_KEY', '')
                if not login or not api_key:
                    raise ConjurUnavailable('Conjur authentication credentials are missing')
                endpoint = f'{base}/authn/{quote(account, safe="")}/{quote(login, safe="")}/authenticate'
                response = client.post(endpoint, content=api_key.encode(), headers={'Content-Type': 'text/plain'})
                response.raise_for_status()
                token = base64.b64encode(response.content).decode('ascii')
            endpoint = f'{base}/secrets/{quote(account, safe="")}/variable/{quote(secret_id, safe="/")}'
            response = client.get(endpoint, headers={'Authorization': f'Token token="{token}"'})
            response.raise_for_status()
            key = base64.b64decode(response.content.strip(), validate=True)
            if len(key) != 32:
                raise ConjurUnavailable('Conjur key must contain 32 base64-encoded bytes')
            return key
    except (httpx.HTTPError, ValueError, OSError) as exc:
        raise ConjurUnavailable('Conjur key retrieval failed') from exc


def encrypt(data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    secret_id = os.getenv('LEXIGRID_CONJUR_KEY_ID', '')
    key = _secret_key(secret_id)
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, data, aad)
    # Store the immutable key identifier with the ciphertext to support rotation.
    header = json.dumps({'key_id': secret_id}, separators=(',', ':')).encode()
    if len(header) > 512:
        raise ConjurError('Conjur key identifier too long')
    return b'CJ1' + nonce, len(header).to_bytes(2, 'big') + header + encrypted


def decrypt(nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(nonce) != 15 or not nonce.startswith(b'CJ1') or len(ciphertext) < 20:
        raise ConjurError('Invalid Conjur evidence envelope')
    header_size = int.from_bytes(ciphertext[:2], 'big')
    if not 1 <= header_size <= 512 or len(ciphertext) < 2 + header_size + 16:
        raise ConjurError('Invalid Conjur envelope header')
    try:
        metadata = json.loads(ciphertext[2:2 + header_size])
        secret_id = metadata['key_id']
        if not isinstance(secret_id, str):
            raise ValueError('Invalid key identifier')
    except (ValueError, KeyError, TypeError) as exc:
        raise ConjurError('Invalid Conjur envelope metadata') from exc
    return AESGCM(_secret_key(secret_id)).decrypt(nonce[3:], ciphertext[2 + header_size:], aad)
