"""Conservative current-exposure checks, independent of the model's prose.
Author: Shahryar Jahangir, Aniza Inc.
"""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import hashlib,json

POLICY_VERSION='current-exposure-v1'


def context_digest(context):
    # Input provenance keeps the exact model payload separately. This digest
    # ignores list ordering and repair instructions when checking current facts.
    def normalize(value,key=None):
        if isinstance(value,dict):return {k:normalize(v,k) for k,v in value.items() if k!='output_requirements'}
        if isinstance(value,list):return sorted((normalize(v) for v in value),key=lambda x:json.dumps(x,sort_keys=True,default=str))
        if key in {'updated_at','created_at','tested_at','submitted_at','assessed_at'}:
            date=_date(value)
            if date is not None:return date.isoformat()
        return value
    return hashlib.sha256(json.dumps(normalize(context),sort_keys=True,default=str).encode()).hexdigest()


def _date(value):
    try:
        result=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except (ValueError,TypeError):return None


def supported_reduction(context,result,dimension,now=None):
    """A citation must explain this dimension and refer to current evidence.

    Mere control existence, attachments, attestations and future work are not
    effectiveness evidence. A passing test is a recorded result, not independent
    verification that every control claim is true.
    """
    now=now or datetime.now(timezone.utc)
    basis=result.get('rating_basis',{}).get(dimension,{})
    if not basis.get('reason','').strip():return []
    cited=set(result.get('evidence_refs',[]))&set(basis.get('evidence_refs',[]))
    if not cited:return []
    latest={}
    for test in context.get('control_tests',[]):
        when=_date(test.get('tested_at'))
        if not when:continue
        ref=test.get('control_ref')
        previous=latest.get(ref)
        if previous is None or (when,(test.get('result')!='pass',str(test.get('ref'))))>previous[0]:latest[ref]=((when,(test.get('result')!='pass',str(test.get('ref')))),test)
    unresolved={x.get('control_ref') for x in context.get('control_findings',[])
                if x.get('severity') in {'high','critical'} and x.get('status')!='closed'}
    for control in context.get('linked_controls',[]):
        ref=control.get('ref');pair=latest.get(ref)
        if control.get('status')!='implemented' or ref not in cited or ref in unresolved or not pair:continue
        (when,_),test=pair
        if test.get('result')=='pass' and test.get('ref') in cited and now-timedelta(days=90)<=when<=now+timedelta(minutes=5):
            return [ref,test['ref']]
    # A newer explicit human assessment can correct exposure without a control.
    # Prior AI-adopted scores and future target assessments cannot corroborate AI.
    changed=_date(context.get('risk',{}).get('updated_at'))
    for assessment in context.get('prior_assessments',[]):
        when=_date(assessment.get('assessed_at'))
        value=assessment.get(dimension)
        if (assessment.get('ref') in cited and assessment.get('kind') in {'inherent','residual'}
            and assessment.get('source')=='human_recorded' and assessment.get('rationale','').strip()
            and type(value) is int and value<=result['recommended_'+dimension] and changed and when
            and changed<=when<=now+timedelta(minutes=5) and now-timedelta(days=90)<=when):
            return [assessment['ref']]
    return []


def guard_assessment(result,context,risk,now=None):
    result=deepcopy(result);model=deepcopy(result);checks=[];support={}
    future=result.get('assessment_timeframe','current')!='current'
    for dimension in ['likelihood','impact']:
        current=getattr(risk,dimension);proposed=result['recommended_'+dimension]
        if future:
            result['recommended_'+dimension]=current
        elif proposed<current:
            support[dimension]=supported_reduction(context,result,dimension,now)
            if not support[dimension]:
                result['recommended_'+dimension]=current
                checks.append('Retained current '+dimension+': no cited, dimension-specific support from a recently passing implemented control or a newer human assessment. Planned controls, evidence metadata, attestations and proposed actions do not justify a reduction.')
    if future:checks.append('The model described a future/target rating. Current likelihood and impact were retained; planned treatments are not completed mitigations.')
    if checks:
        result['confidence']='low'
        controls=context.get('linked_controls',[])
        implemented=sum(c.get('status')=='implemented' for c in controls)
        planned=sum(c.get('status')=='planned' for c in controls)
        result['rationale']=('The evidence-checked current-exposure proposal is likelihood '+str(result['recommended_likelihood'])+' and impact '+str(result['recommended_impact'])+'. The linked snapshot contains '+str(implemented)+' implemented controls, '+str(planned)+' planned controls and '+str(len(context.get('control_tests',[])))+' recorded control tests. Unsupported reductions were not used. Missing records and future treatments do not demonstrate reduced exposure.')
        result['limitations']=list(dict.fromkeys(checks+result.get('limitations',[])))[:25]
    elif not context.get('control_tests') and not context.get('prior_assessments'):
        result['confidence']='low'
    # Keep unapproved inherent/residual estimates only inside the original
    # model assessment; they must not look like the checked current rating.
    for prefix in ('inherent','residual'):
        likelihood=model.get(prefix+'_likelihood');impact=model.get(prefix+'_impact')
        if likelihood is not None and impact is not None:model[prefix+'_score']=likelihood*impact
        for suffix in ('likelihood','impact','score'):result.pop(prefix+'_'+suffix,None)
    result['model_assessment']=model
    result['score_checks']=checks
    result['reduction_support']=support
    result['assessment_policy']=POLICY_VERSION
    result['assessment_timeframe']='current'
    result['baseline_likelihood']=risk.likelihood;result['baseline_impact']=risk.impact
    result['proposed_score']=result['recommended_likelihood']*result['recommended_impact']
    result['evidence_snapshot_sha256']=context_digest(context)
    return result
