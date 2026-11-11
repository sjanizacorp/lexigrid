"""Browser handoff for configured federation providers.
Author: Shahryar Jahangir, Aniza Inc.
"""
import json
import os
import secrets
from fastapi import HTTPException
from fastapi.responses import HTMLResponse, JSONResponse


def providers():
    from .oidc import configuration
    from .saml_sso import settings
    available=[]
    for protocol,validate in (('oidc',configuration),('saml',settings)):
        try:
            validate()
        except (HTTPException,RuntimeError):
            continue
        available.append({'protocol':protocol,'label':os.getenv(
            'LEXIGRID_'+protocol.upper()+'_LABEL','Organization SSO ('+protocol.upper()+')')[:100]})
    return available


def login_response(payload,tenant_id,browser=False):
    if not browser:
        result=JSONResponse(payload)
    else:
        nonce=secrets.token_urlsafe(24)
        data=json.dumps({'access_token':payload['access_token'],'tenant_id':tenant_id}).replace('<','\\u003c')
        result=HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<title>Signing in to LexiGrid</title><p>Completing secure sign-in…</p>'
            f'<script nonce="{nonce}">const session={data};'
            'sessionStorage.setItem("lexigrid_token",session.access_token);'
            'sessionStorage.setItem("lexigrid_tenant",session.tenant_id);'
            'location.replace("/ui");</script></html>')
        result.headers['Content-Security-Policy']=(
            f"default-src 'none'; script-src 'nonce-{nonce}'; base-uri 'none'; frame-ancestors 'none'")
    result.headers['Cache-Control']='no-store'
    result.headers['Referrer-Policy']='no-referrer'
    result.headers['X-Content-Type-Options']='nosniff'
    return result
