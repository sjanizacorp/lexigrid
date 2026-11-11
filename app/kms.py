"""Vault Transit-backed encryption with authenticated context and local legacy fallback.
Shahryar Jahangir / Aniza Inc.
"""
import base64, os, httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class TransitError(RuntimeError): pass

def provider():
    """Missing configuration retains legacy local mode; invalid explicit values do not."""
    selected=os.getenv('LEXIGRID_KMS_PROVIDER','local')
    if selected not in ('local','vault','conjur'):
        raise TransitError('Evidence encryption provider must be local, vault or conjur')
    return selected


def _request(operation, payload):
    url=os.environ.get('LEXIGRID_VAULT_ADDR','').rstrip('/')
    token=os.environ.get('LEXIGRID_VAULT_TOKEN','')
    key=os.environ.get('LEXIGRID_VAULT_TRANSIT_KEY','lexigrid')
    mount=os.environ.get('LEXIGRID_VAULT_TRANSIT_MOUNT','transit')
    if not url.startswith('https://') or not token or not key.isidentifier() or not mount.isidentifier():
        raise TransitError('Vault Transit requires HTTPS, a token, and valid mount/key names')
    try:
        with httpx.Client(timeout=8,verify=os.environ.get('LEXIGRID_VAULT_CA_BUNDLE') or True) as client:
            response=client.post(f'{url}/v1/{mount}/{operation}/{key}',json=payload,headers={'X-Vault-Token':token})
            response.raise_for_status()
            result=response.json()
            if not isinstance(result,dict) or not isinstance(result.get('data'),dict):
                raise ValueError('Invalid Transit response')
            data=result['data']
            field='plaintext' if operation=='decrypt' else 'ciphertext'
            if not isinstance(data.get(field),str) or (field=='ciphertext' and not data[field]):
                raise ValueError('Invalid Transit result')
            return data
    except (httpx.HTTPError,KeyError,ValueError,TypeError,OSError) as exc:
        raise TransitError('Vault Transit operation failed') from exc

def encrypt(data:bytes, context:bytes)->str:
    payload={'plaintext':base64.b64encode(data).decode(), 'context':base64.b64encode(context).decode()}
    return _request('encrypt',payload)['ciphertext']

def decrypt(ciphertext:str, context:bytes)->bytes:
    result=_request('decrypt',{'ciphertext':ciphertext,'context':base64.b64encode(context).decode()})
    try:
        return base64.b64decode(result['plaintext'],validate=True)
    except (ValueError,TypeError) as exc:
        raise TransitError('Vault Transit operation failed') from exc

def rewrap(ciphertext:str,context:bytes)->str:
    return _request('rewrap',{'ciphertext':ciphertext,'context':base64.b64encode(context).decode()})['ciphertext']

def encrypt_evidence(data:bytes,aad:bytes,legacy_key:bytes|None=None):
    selected=provider()
    if selected=='conjur':
        from .conjur_kms import encrypt as conjur_encrypt
        return conjur_encrypt(data,aad)
    if selected=='vault':
        return b'VAULT1',encrypt(data,aad).encode()
    if legacy_key is None or len(legacy_key)!=32: raise TransitError('Local encryption key unavailable')
    nonce=os.urandom(12)
    return nonce,AESGCM(legacy_key).encrypt(nonce,data,aad)

def decrypt_evidence(nonce:bytes,ciphertext:bytes,aad:bytes,legacy_key:bytes|None=None):
    if nonce.startswith(b'CJ1'):
        from .conjur_kms import decrypt as conjur_decrypt
        return conjur_decrypt(nonce,ciphertext,aad)
    if nonce==b'VAULT1': return decrypt(ciphertext.decode(),aad)
    if legacy_key is None or len(legacy_key)!=32: raise TransitError('Legacy evidence key required')
    return AESGCM(legacy_key).decrypt(nonce,ciphertext,aad)
