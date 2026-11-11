"""Read-only identity observations and deterministic, scope-bounded checks.
Author: Shahryar Jahangir, Aniza Inc.
"""
from datetime import datetime,timedelta,timezone
from urllib.parse import urlparse
import hashlib,json
import httpx

GRAPH='https://graph.microsoft.com/v1.0'
MAX_BYTES=20*1024*1024


class CollectionError(Exception):pass


def collect_entra(config,client=None):
    """No Microsoft write APIs; redirects/proxies and foreign pagination are refused."""
    owned=client is None
    client=client or httpx.Client(timeout=httpx.Timeout(45,connect=10),follow_redirects=False,trust_env=False)
    try:
        response=client.post('https://login.microsoftonline.com/'+config['directory_tenant_id']+'/oauth2/v2.0/token',data={'client_id':config['client_id'],'client_secret':config['client_secret'],'grant_type':'client_credentials','scope':'https://graph.microsoft.com/.default'})
        if response.status_code!=200:raise CollectionError('Microsoft token request failed (HTTP '+str(response.status_code)+'). Verify the app registration, tenant and consent.')
        token_response=response.json()
        if not isinstance(token_response,dict):raise CollectionError('Microsoft returned an invalid token response')
        token=token_response.get('access_token')
        if not isinstance(token,str) or not token:raise CollectionError('Microsoft did not return an access token')
        headers={'Authorization':'Bearer '+token};total=0
        def read(resource,params=None,many=False):
            nonlocal total
            url=GRAPH+resource;seen=set();items=[];first=True
            while url:
                parsed=urlparse(url)
                if parsed.scheme!='https' or parsed.netloc!='graph.microsoft.com' or parsed.path!='/v1.0'+resource or parsed.fragment or parsed.username:raise CollectionError('Microsoft pagination target was not an approved resource')
                if url in seen:raise CollectionError('Microsoft returned repeating pagination')
                seen.add(url);response=client.get(url,headers=headers,params=params if first else None);first=False
                if response.status_code!=200:raise CollectionError('Microsoft read failed (HTTP '+str(response.status_code)+'). Check read-only permissions and licensing.')
                total+=len(response.content)
                if total>MAX_BYTES:raise CollectionError('Identity snapshot exceeds the collection byte budget; no complete snapshot was produced. Reduce the observation period.')
                value=response.json()
                if not isinstance(value,dict):raise CollectionError('Microsoft returned invalid data')
                if not many:return value
                if not isinstance(value.get('value'),list) or any(not isinstance(x,dict) for x in value['value']):raise CollectionError('Microsoft returned an invalid collection')
                items.extend(value['value']);url=value.get('@odata.nextLink')
                if url is not None and not isinstance(url,str):raise CollectionError('Microsoft returned invalid pagination')
            return items
        since=(datetime.now(timezone.utc)-timedelta(days=config.get('lookback_days',7))).isoformat().replace('+00:00','Z')
        datasets={};errors={}
        for name,resource,params,many in [
            ('security_defaults','/policies/identitySecurityDefaultsEnforcementPolicy',None,False),
            ('conditional_access','/identity/conditionalAccess/policies',None,True),
            ('sign_ins','/auditLogs/signIns',{'$filter':'createdDateTime ge '+since,'$select':'id,createdDateTime,status,authenticationRequirement,conditionalAccessStatus,isInteractive,authenticationDetails','$top':'1000'},True)]:
            try:datasets[name]=read(resource,params,many)
            except (CollectionError,httpx.HTTPError,ValueError,TypeError,KeyError) as exc:
                errors[name]=str(exc) if isinstance(exc,CollectionError) else 'Identity read failed; inspect permissions and service availability.'
        return {'source':'entra_live','directory_tenant_id':config['directory_tenant_id'],'collected_at':datetime.now(timezone.utc).isoformat(),'observation_start':since,'datasets':datasets,'errors':errors,'transport':'Microsoft Graph HTTPS; read-only GET resources','complete':not errors}
    except (httpx.HTTPError,ValueError,TypeError,KeyError) as exc:raise CollectionError('Microsoft identity collection failed; no credentials or provider response were logged.') from None
    finally:
        if owned:client.close()


def check(key,title,dimension,result,criteria,observed,limitations=None):
    return {'id':key,'title':title,'dimension':dimension,'result':result,'criteria':criteria,'observed':observed,'limitations':limitations or []}


def evaluate_entra(snapshot):
    data=snapshot.get('datasets',{});errors=snapshot.get('errors',{});out=[]
    defaults=data.get('security_defaults',{});enabled=defaults.get('isEnabled') if isinstance(defaults,dict) else None
    out.append(check('entra.security_defaults','Security defaults configuration','implementation','passed' if enabled is True else 'failed' if enabled is False else 'insufficient_evidence','Security defaults isEnabled is true.',{'isEnabled':enabled},['This configuration test does not prove complete MFA coverage or operating effectiveness.']+[errors['security_defaults']] if 'security_defaults' in errors else ['This configuration test does not prove complete MFA coverage or operating effectiveness.']))
    policies=data.get('conditional_access');valid=isinstance(policies,list)
    enabled_policies=[x for x in policies if isinstance(x,dict) and x.get('state')=='enabled'] if valid else []
    def grants(policy):
        value=policy.get('grantControls',{});return value if isinstance(value,dict) else {}
    def controls(policy):
        value=grants(policy).get('builtInControls',[])
        return value if isinstance(value,list) and all(isinstance(x,str) for x in value) else []
    def strength(policy):
        value=grants(policy).get('authenticationStrength')
        return isinstance(value,dict) and isinstance(value.get('id'),str) and bool(value['id'])
    mfa=[x for x in enabled_policies if 'mfa' in controls(x) or strength(x)]
    out.append(check('entra.mfa_policy_present','Enabled MFA or authentication-strength policy present','implementation','passed' if mfa else 'failed' if valid else 'insufficient_evidence','At least one enabled policy specifies MFA or authentication strength.',{'enabled_policies':len(enabled_policies),'mfa_or_strength_policies':len(mfa)},['Presence does not prove scope coverage: exclusions, conditions, OR grants and authentication-strength definitions require review.']+([errors['conditional_access']] if 'conditional_access' in errors else [])))
    blocked=[]
    for row in enabled_policies:
        conditions=row.get('conditions') or {};types=conditions.get('clientAppTypes',[]) if isinstance(conditions,dict) else []
        if isinstance(types,list) and all(isinstance(x,str) for x in types) and 'block' in controls(row) and {'exchangeActiveSync','other'}<=set(types):blocked.append(row)
    out.append(check('entra.legacy_block_policy','Enabled legacy-client blocking policy present','implementation','passed' if blocked else 'failed' if valid else 'insufficient_evidence','An enabled policy blocks exchangeActiveSync and other legacy clients.',{'matching_policies':len(blocked)},['Policy conditions and exclusions can narrow actual protection; presence alone is not enforcement proof.']))
    events=data.get('sign_ins');valid=isinstance(events,list)
    successful=[x for x in events if isinstance(x,dict) and x.get('isInteractive') is True and isinstance(x.get('status'),dict) and type(x['status'].get('errorCode')) is int and x['status']['errorCode']==0] if valid else []
    mfa_count=sum(x.get('authenticationRequirement')=='multiFactorAuthentication' for x in successful)
    complete=valid and 'sign_ins' not in errors
    out.append(check('entra.observed_interactive_mfa','MFA reported on successful interactive sign-ins','effectiveness','passed' if complete and successful and mfa_count==len(successful) else 'failed' if complete and successful and mfa_count<len(successful) else 'insufficient_evidence','Every successful interactive sign-in in the retrieved observation period reports multiFactorAuthentication.',{'successful_interactive_signins':len(successful),'reported_mfa':mfa_count,'observation_start':snapshot.get('observation_start'),'complete_collection':complete},['This is a bounded historical sample reported by Entra. It does not independently challenge credentials or establish protection for unobserved accounts, apps, sessions or future sign-ins.']+([errors['sign_ins']] if 'sign_ins' in errors else [])))
    return out


def evaluate_ad(snapshot,minimum_length=14,max_lockout_threshold=10):
    data=snapshot.get('datasets',{});users=data.get('enabled_users');policies=data.get('effective_password_policies')
    complete=snapshot.get('complete') is True and isinstance(users,list) and isinstance(policies,list) and bool(policies) and all(isinstance(x,dict) for x in users+policies)
    if complete:
        policy_names={x.get('Identity') for x in policies if isinstance(x.get('Identity'),str)}
        complete=bool(policy_names) and all(isinstance(x.get('EffectivePolicy'),str) and x['EffectivePolicy'] in policy_names for x in users)
    out=[]
    for key,title,criteria,field,predicate in [
        ('ad.password_length','Effective minimum password length','Every collected effective policy has MinPasswordLength >= '+str(minimum_length)+'.','MinPasswordLength',lambda x:type(x) is int and x>=minimum_length),
        ('ad.reversible_encryption','Reversible password encryption disabled','Every effective policy explicitly disables reversible encryption.','ReversibleEncryptionEnabled',lambda x:x is False),
        ('ad.lockout','Effective lockout threshold','Every effective policy has a threshold from 1 through '+str(max_lockout_threshold)+'.','LockoutThreshold',lambda x:type(x) is int and 1<=x<=max_lockout_threshold)]:
        values=[x.get(field) for x in policies] if complete else []
        known=complete and all(type(value) is (bool if field=='ReversibleEncryptionEnabled' else int) for value in values)
        out.append(check(key,title,'implementation','passed' if known and all(predicate(x) for x in values) else 'failed' if known else 'insufficient_evidence',criteria,{'policies':len(values),'nonconforming':sum(not predicate(x) for x in values)},['Thresholds are organization-selected criteria, not a universal requirement of every standard. Uploaded collector data requires provenance review.']))
    for key,title,field in [('ad.password_required','Enabled accounts require a password','PasswordNotRequired'),('ad.kerberos_preauth','Kerberos preauthentication required','DoesNotRequirePreAuth'),('ad.unconstrained_delegation','No unreviewed unconstrained delegation flags','TrustedForDelegation')]:
        values=[x.get(field) for x in users] if complete else []
        known=complete and bool(users) and all(type(value) is bool for value in values)
        out.append(check(key,title,'implementation','passed' if known and not any(values) else 'failed' if known else 'insufficient_evidence','No collected enabled account has '+field+' set to true.',{'enabled_accounts':len(values),'flagged_accounts':sum(x is True for x in values)},['An account flag check is not a complete identity or privilege audit. Any authorized exception needs documented review.']))
    events=data.get('security_event_counts',{})
    available=isinstance(events,dict) and type(events.get('4624')) is int and events['4624']>0 and snapshot.get('event_collection_complete') is True
    out.append(check('ad.logon_observation','Successful logon records observed','effectiveness','passed' if available else 'insufficient_evidence','Read-only collector retrieved successful logon event 4624 during its stated period without a collection error.',{'successful_logon_events':events.get('4624') if isinstance(events,dict) else None},['Event existence establishes only sampled logging activity. It does not prove alerting, complete audit policy, retention, MFA or protection of every domain controller. Operator-submitted snapshots are not independently authenticated by LexiGrid.']))
    return out


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
