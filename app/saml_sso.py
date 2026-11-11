"""SAML 2.0 SP adapter using OneLogin's signed XML validation.
No JIT user provisioning. SAML identity must be bound by an administrator.
"""
import binascii
import os
from fastapi import HTTPException

def mfa_contexts():
    """Operator-approved IdP assertions that mean multiple factors were used."""
    raw = os.getenv('LEXIGRID_SAML_MFA_CONTEXTS',
                    'https://refeds.org/profile/mfa,https://refeds.org/profile/mfa/phr')
    values = list(dict.fromkeys(value.strip() for value in raw.split(',') if value.strip()))
    if not values or len(values) > 16 or any(
        len(value) > 512 or not value.startswith(('https://','http://','urn:'))
        or any(char.isspace() for char in value) for value in values
    ):
        raise HTTPException(503,'SAML MFA authentication contexts are not configured correctly')
    return values


def settings():
    required=('LEXIGRID_SAML_SP_ENTITY_ID','LEXIGRID_SAML_ACS_URL','LEXIGRID_SAML_IDP_ENTITY_ID','LEXIGRID_SAML_IDP_SSO_URL','LEXIGRID_SAML_IDP_CERT')
    if any(not os.environ.get(k) for k in required): raise RuntimeError('SAML configuration is incomplete')
    if not os.environ['LEXIGRID_SAML_ACS_URL'].startswith('https://'): raise RuntimeError('SAML ACS must use HTTPS')
    return {'strict':True,'debug':False,'sp':{'entityId':os.environ['LEXIGRID_SAML_SP_ENTITY_ID'],'assertionConsumerService':{'url':os.environ['LEXIGRID_SAML_ACS_URL'],'binding':'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'},'x509cert':'','privateKey':''},'idp':{'entityId':os.environ['LEXIGRID_SAML_IDP_ENTITY_ID'],'singleSignOnService':{'url':os.environ['LEXIGRID_SAML_IDP_SSO_URL'],'binding':'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'},'x509cert':os.environ['LEXIGRID_SAML_IDP_CERT'].replace('\\n','\n')},'security':{'wantAssertionsSigned':True,'wantMessagesSigned':True,'wantNameId':True,'wantNameIdEncrypted':False,'wantAssertionsEncrypted':False,'wantAttributeStatement':False,'requestedAuthnContext':mfa_contexts() if os.getenv('LEXIGRID_REQUIRE_MFA')=='1' else False,'requestedAuthnContextComparison':'exact','wantXMLValidation':True,'rejectDeprecatedAlgorithm':True,'signatureAlgorithm':'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256','digestAlgorithm':'http://www.w3.org/2001/04/xmlenc#sha256'}}

def saml_auth(request, post_data=None):
    try: from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError as exc: raise RuntimeError('Install python3-saml with its XML security dependencies') from exc
    proto=os.environ.get('LEXIGRID_PUBLIC_SCHEME','https')
    if proto!='https': raise RuntimeError('SAML requires HTTPS')
    data={'https':'on','http_host':os.environ.get('LEXIGRID_PUBLIC_HOST','localhost'),'script_name':request.url.path,'server_port':'443','get_data':dict(request.query_params),'post_data':post_data or {}}
    return OneLogin_Saml2_Auth(data,settings())

def validate_response(auth, expected_request_id):
    from lxml.etree import XMLSyntaxError
    from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
    try:
        auth.process_response(request_id=expected_request_id)
    except (binascii.Error, XMLSyntaxError, UnicodeError, ValueError,
            OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError) as exc:
        raise HTTPException(401,'SAML assertion validation failed') from exc
    if auth.get_errors() or not auth.is_authenticated(): raise HTTPException(401,'SAML assertion validation failed')
    if os.getenv('LEXIGRID_REQUIRE_MFA') == '1':
        # The toolkit exposes contexts from the assertion only after validating
        # signatures, issuer, audience, timestamps and request correlation.
        contexts = auth.get_last_authn_contexts()
        approved = mfa_contexts()
        if not isinstance(contexts,list) or not any(value in approved for value in contexts):
            raise HTTPException(403,'Identity provider must assert multifactor authentication')
    issuer=auth.get_last_assertion_id()
    subject=auth.get_nameid()
    response_id=auth.get_last_message_id()
    if not issuer or not subject or not response_id: raise HTTPException(401,'Incomplete SAML assertion')
    return {'subject':subject,'response_id':response_id,'assertion_id':issuer}
