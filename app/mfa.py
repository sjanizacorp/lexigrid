"""RFC 6238 TOTP implementation and authenticated encryption. LexiGrid / Aniza Inc."""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _key():
    """Decode current base64url keys and legacy installer-generated 64-char hex keys.

    Never regenerate an existing key: doing so would make enrolled MFA secrets unreadable.
    """
    raw = os.environ.get('LEXIGRID_MFA_ENCRYPTION_KEY', '').strip()
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    try:
        key = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError('Invalid MFA encryption key encoding') from exc
    if len(key) != 32:
        raise RuntimeError('LEXIGRID_MFA_ENCRYPTION_KEY must be a 32-byte base64url key or legacy 64-character hex key')
    return key


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def seal(secret, user_id):
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, secret.encode(), user_id.encode())
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def unseal(encoded, user_id):
    raw = base64.urlsafe_b64decode(encoded)
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], user_id.encode()).decode()


def totp(secret, counter):
    raw = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    digest = hmac.new(raw, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff
    return f'{number % 1000000:06d}'


def verify(secret, code, now=None, last_counter=-1):
    code=normalize_code(code)
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int(time.time() if now is None else now) // 30
    for counter in (current - 1, current, current + 1):
        if counter > last_counter and counter >= 0 and hmac.compare_digest(totp(secret, counter), code):
            return counter
    return None


def local_required():
    value=os.getenv('LEXIGRID_REQUIRE_LOCAL_MFA',os.getenv('LEXIGRID_REQUIRE_MFA','0'))
    if value not in {'0','1'}:raise RuntimeError('Local MFA policy must be 0 or 1')
    return value=='1'


def normalize_code(code):
    if not isinstance(code,str) or len(code)>32:return ''
    import unicodedata
    value=''.join(code.split())
    try:return ''.join(str(unicodedata.decimal(char)) for char in value)
    except (TypeError,ValueError):return ''


def setup_payload(secret,email):
    """Offline, standard SHA-1/6-digit/30-second authenticator QR."""
    from urllib.parse import quote,urlencode
    from reportlab.graphics.barcode import qrencoder
    from PIL import Image,ImageDraw
    import io
    uri='otpauth://totp/'+quote('LexiGrid:'+email,safe='')+'?'+urlencode(
        {'secret':secret,'issuer':'LexiGrid','algorithm':'SHA1','digits':6,'period':30})
    qr=qrencoder.QRCode(None,qrencoder.QRErrorCorrectLevel.M);qr.addData(uri);qr.make()
    border,scale=4,8;size=(qr.getModuleCount()+border*2)*scale
    image=Image.new('RGB',(size,size),'white');draw=ImageDraw.Draw(image)
    for row,values in enumerate(qr.modules):
        for column,dark in enumerate(values):
            if dark:
                x,y=(column+border)*scale,(row+border)*scale
                draw.rectangle((x,y,x+scale-1,y+scale-1),fill='black')
    output=io.BytesIO();image.save(output,format='PNG')
    return {'secret':secret,'account':email,'otpauth_uri':uri,
            'qr_code_data_url':'data:image/png;base64,'+base64.b64encode(output.getvalue()).decode(),
            'server_time':int(time.time()),'period':30}
