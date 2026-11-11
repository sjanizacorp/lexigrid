"""OIDC authorization-code + PKCE integration. Author: Shahryar Jahangir, Aniza Inc.

Requires a trusted, tenant-controlled OIDC issuer (including offline IdPs).
Only pre-provisioned users may sign in; no JIT role or tenant assignment.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlencode
import httpx
import jwt
from fastapi import HTTPException


def mfa_acrs():
    values=[v.strip() for v in os.getenv('LEXIGRID_OIDC_MFA_ACRS','').split(',') if v.strip()]
    if len(values)>16 or any(len(value)>100 or not value.isalnum() for value in values):
        raise HTTPException(503,'OIDC MFA authentication contexts are invalid')
    return values


def configuration():
    issuer=os.getenv('LEXIGRID_OIDC_ISSUER','').rstrip('/')
    client=os.getenv('LEXIGRID_OIDC_CLIENT_ID','')
    secret=os.getenv('LEXIGRID_OIDC_CLIENT_SECRET','')
    redirect=os.getenv('LEXIGRID_OIDC_REDIRECT_URI','')
    if not all((issuer,client,redirect)) or not issuer.startswith('https://') or not redirect.startswith('https://'):
        raise HTTPException(503,'OIDC is not configured with HTTPS endpoints')
    return issuer,client,secret,redirect


def discovery(issuer):
    try:
        with httpx.Client(timeout=8.0,follow_redirects=False) as client:
            r=client.get(issuer+'/.well-known/openid-configuration')
            r.raise_for_status(); doc=r.json()
    except (httpx.HTTPError,ValueError) as e:
        raise HTTPException(503,'Identity provider unavailable') from e
    if not isinstance(doc,dict):
        raise HTTPException(503,'Identity provider metadata invalid')
    if doc.get('issuer')!=issuer:
        raise HTTPException(503,'Identity provider issuer mismatch')
    for key in ('authorization_endpoint','token_endpoint','jwks_uri'):
        if not str(doc.get(key,'')).startswith('https://'):
            raise HTTPException(503,'Identity provider metadata invalid')
    return doc


def state_token(secret,tenant,nonce,verifier,browser=False):
    payload={'tenant':tenant,'nonce':nonce,'verifier':verifier,'iat':int(time.time()),'exp':int(time.time())+300,'browser':browser}
    return jwt.encode(payload,secret,algorithm='HS256')


def parse_state(token,secret):
    try:
        return jwt.decode(token,secret,algorithms=['HS256'],options={'require':['exp','iat','tenant','nonce','verifier']})
    except jwt.PyJWTError as e:
        raise HTTPException(401,'Invalid or expired OIDC login state') from e


def begin(tenant,secret,browser=False):
    issuer,client,_,redirect=configuration()
    doc=discovery(issuer)
    nonce=secrets.token_urlsafe(32)
    verifier=secrets.token_urlsafe(48)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    state=state_token(secret,tenant,nonce,verifier,browser=browser)
    parameters={'response_type':'code','client_id':client,'redirect_uri':redirect,'scope':'openid email profile','state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'}
    if os.getenv('LEXIGRID_REQUIRE_MFA')=='1' and mfa_acrs():
        parameters['claims']=json.dumps({'id_token':{'acrs':{'essential':True,'values':mfa_acrs()}}})
    url=doc['authorization_endpoint']+'?'+urlencode(parameters)
    return url,state


def exchange_with_verifier(code,verifier,expected_nonce):
    issuer,client,client_secret,redirect=configuration()
    doc=discovery(issuer)
    payload={'grant_type':'authorization_code','code':code,'redirect_uri':redirect,'client_id':client,'code_verifier':verifier}
    if client_secret: payload['client_secret']=client_secret
    try:
        with httpx.Client(timeout=10.0,follow_redirects=False) as http:
            response=http.post(doc['token_endpoint'],data=payload,headers={'Accept':'application/json'})
            response.raise_for_status(); tokens=response.json()
            keys=http.get(doc['jwks_uri']);keys.raise_for_status();jwks=keys.json()
    except (httpx.HTTPError,ValueError) as e:
        raise HTTPException(502,'Identity provider token exchange failed') from e
    if not isinstance(tokens,dict) or not isinstance(jwks,dict):
        raise HTTPException(502,'Identity provider token exchange failed')
    token=tokens.get('id_token')
    if not isinstance(token,str):raise HTTPException(401,'Missing ID token')
    try:
        header=jwt.get_unverified_header(token)
        if header.get('alg') not in ('RS256','RS384','RS512','ES256','ES384','ES512'):
            raise ValueError('Unsupported signing algorithm')
        key=next(k for k in jwks['keys'] if k.get('kid')==header.get('kid') and k.get('use','sig')=='sig')
        claims=jwt.decode(token,jwt.PyJWK.from_dict(key).key,algorithms=[header['alg']],audience=client,issuer=issuer,options={'require':['exp','iat','iss','aud','sub','nonce']},leeway=30)
    except (jwt.PyJWTError,ValueError,KeyError,StopIteration,TypeError,AttributeError) as e:
        raise HTTPException(401,'Invalid identity token') from e
    if ('azp' in claims and claims['azp'] != client) or (
        isinstance(claims.get('aud'),list) and len(claims['aud'])>1 and claims.get('azp')!=client
    ):
        raise HTTPException(401,'Invalid identity token authorized party')
    if not isinstance(claims.get('sub'),str) or not claims['sub'].strip():
        raise HTTPException(401,'Missing identity subject')
    if not hmac.compare_digest(str(claims.get('nonce','')),expected_nonce):
        raise HTTPException(401,'OIDC nonce mismatch')
    if os.getenv('LEXIGRID_REQUIRE_MFA')=='1':
        amr=claims.get('amr',[])
        acrs=claims.get('acrs',[])
        explicit=isinstance(amr,list) and ('mfa' in amr or ('pwd' in amr and any(
            value in amr for value in ('otp','hwk','swk','fido','webauthn'))))
        context=isinstance(acrs,list) and any(value in mfa_acrs() for value in acrs)
        if not explicit and not context:
            raise HTTPException(403,'Identity provider must assert multifactor authentication')
    return claims
