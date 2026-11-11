"""S3 Object Lock Compliance mode audit checkpoint publisher.
Requires preconfigured versioned Object Lock bucket and independent credentials.
"""
import hashlib, json, os
from datetime import datetime,timezone,timedelta
from .audit_anchor import canonical,checkpoint_digest

class RetentionError(RuntimeError): pass

def publish(checkpoint, client, bucket, prefix='lexigrid/audit/', retention_days=365):
    if retention_days<1: raise RetentionError('Retention must be positive')
    key=f"{prefix.rstrip('/')}/{checkpoint['generated_at'].replace(':','-')}-{checkpoint_digest(checkpoint)}.json"
    body=canonical(checkpoint)
    until=datetime.now(timezone.utc)+timedelta(days=retention_days)
    response=client.put_object(Bucket=bucket,Key=key,Body=body,ContentType='application/json',ChecksumAlgorithm='SHA256',ObjectLockMode='COMPLIANCE',ObjectLockRetainUntilDate=until)
    if not response.get('VersionId'): raise RetentionError('Object Lock destination did not return a version ID')
    fetched=client.get_object(Bucket=bucket,Key=key,VersionId=response['VersionId'])
    if hashlib.sha256(fetched['Body'].read()).digest()!=hashlib.sha256(body).digest(): raise RetentionError('Remote checkpoint hash mismatch')
    retention=client.get_object_retention(Bucket=bucket,Key=key,VersionId=response['VersionId'])['Retention']
    if retention.get('Mode')!='COMPLIANCE' or retention['RetainUntilDate']<until-timedelta(seconds=5):
        raise RetentionError('Remote Object Lock compliance retention not confirmed')
    return {'bucket':bucket,'key':key,'version_id':response['VersionId'],'sha256':hashlib.sha256(body).hexdigest(),'retained_until':retention['RetainUntilDate'].isoformat()}

def main():
    import boto3
    from .main import SessionLocal
    from .audit_anchor import build_checkpoint, load_audit_records
    key=os.getenv('LEXIGRID_ANCHOR_HMAC_KEY','')
    bucket=os.environ['LEXIGRID_AUDIT_WORM_BUCKET']
    client=boto3.client('s3',endpoint_url=os.environ.get('LEXIGRID_S3_ENDPOINT') or None)
    with SessionLocal() as s:
        records=load_audit_records(s, os.getenv('LEXIGRID_AUDIT_TENANT_ID') or None)
        checkpoint=build_checkpoint(records,key)
    result=publish(checkpoint,client,bucket,retention_days=int(os.getenv('LEXIGRID_AUDIT_RETENTION_DAYS','365')))
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
