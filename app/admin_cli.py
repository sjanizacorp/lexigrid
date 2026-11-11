"""Audited initial tenant provisioning and credential recovery.
Run with the migration/owner DATABASE_URL, never the restricted API account.
Author: Shahryar Jahangir, Aniza Inc.
"""
from .database_identity import validate_database_identity
import argparse
import getpass
import json
import socket
import os
import uuid
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from argon2 import PasswordHasher


def operator_event(session,tenant_id,action,object_id,target_user_id,**extra):
    """Record process/database operator context, never impersonate the affected user."""
    from .main import Audit,utc,audit_digest,AUDIT_HMAC_KEY
    uid=os.getuid() if hasattr(os,'getuid') else None
    try:
        import pwd
        account=pwd.getpwuid(uid).pw_name
    except (ImportError,KeyError,TypeError):
        account=getpass.getuser()
    role=session.scalar(text('SELECT current_user')) if session.bind.dialect.name=='postgresql' else 'sqlite-file-operator'
    host=socket.gethostname()
    actor=str(uuid.uuid5(uuid.NAMESPACE_URL,f'lexigrid:admin-cli:{host}:{uid}:{account}:{role}'))
    details=json.dumps({'source':'admin_cli','operator':{'kind':'database_owner_cli',
        'database_role':role,'host':host,'os_uid':uid,'os_account':account,
        'assurance':'process_and_database_context'},'target_user_id':target_user_id,**extra},sort_keys=True)
    at=utc()
    mac=audit_digest(tenant_id,actor,action,object_id,details,at) if AUDIT_HMAC_KEY else None
    session.add(Audit(tenant_id=tenant_id,at=at,actor_id=actor,action=action,
                     object_id=object_id,details=details,integrity_mac=mac))


def provision_tenant(engine, name, email, password, role="tenant_admin"):
    from .main import Tenant, User, Audit, uid, utc, audit_digest, AUDIT_HMAC_KEY
    if role not in ('tenant_admin','platform_admin'):
        raise ValueError('Initial administrator role must be tenant_admin or platform_admin')
    if len(password) < 16:
        raise ValueError('Administrator password must contain at least 16 characters')
    if not name.strip() or '@' not in email:
        raise ValueError('Valid organization name and email required')
    if engine.dialect.name not in ('postgresql', 'sqlite'):
        raise RuntimeError('Unsupported database')
    tenant_id=str(uuid.uuid4()); user_id=str(uuid.uuid4())
    with Session(engine) as s, s.begin():
        if engine.dialect.name=='postgresql':
            # FORCE RLS applies to owner too; set the context for the entire transaction.
            s.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"), {'tenant':tenant_id})
        if s.scalar(select(Tenant.id).where(Tenant.name==name.strip())):
            raise ValueError('Organization already exists')
        s.add(Tenant(id=tenant_id,name=name.strip()))
        s.flush()
        s.add(User(id=user_id,tenant_id=tenant_id,email=email.strip().lower(),
                   password_hash=PasswordHasher().hash(password),role=role,active=1,token_version=1))
        s.flush()
        operator_event(s,tenant_id,'tenant.bootstrap',tenant_id,user_id,initial_role=role)
    return tenant_id


def reset_password(engine, tenant_id, email, password):
    from .main import User, Audit, utc, audit_digest, AUDIT_HMAC_KEY
    tenant_id=str(uuid.UUID(tenant_id))
    if len(password)<16: raise ValueError('Password must contain at least 16 characters')
    with Session(engine) as s, s.begin():
        if engine.dialect.name=='postgresql':
            s.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"),{'tenant':tenant_id})
        user=s.scalar(select(User).where(User.tenant_id==tenant_id,User.email==email.strip().lower()))
        if not user: raise ValueError('Account not found')
        s.execute(update(User).where(User.id==user.id,User.tenant_id==tenant_id).values(
            password_hash=PasswordHasher().hash(password),token_version=User.token_version+1),
            execution_options={'synchronize_session':False})
        operator_event(s,tenant_id,'auth.password.admin_reset',user.id,user.id)
    return True


def bind_oidc_identity(engine, tenant_id, email, issuer, subject):
    """Bind a verified, externally established IdP identity to a provisioned user."""
    from .main import User, Audit, utc, audit_digest, AUDIT_HMAC_KEY
    tenant_id=str(uuid.UUID(tenant_id))
    if not issuer.startswith('https://') or not subject or len(issuer)>512 or len(subject)>512:
        raise ValueError('Valid HTTPS issuer and nonempty subject required')
    with Session(engine) as s, s.begin():
        if engine.dialect.name=='postgresql':
            s.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"),{'tenant':tenant_id})
        user=s.scalar(select(User).where(User.tenant_id==tenant_id,User.email==email.strip().lower()))
        if not user: raise ValueError('Account not found')
        duplicate=s.scalar(select(User.id).where(User.tenant_id==tenant_id,User.oidc_issuer==issuer,User.oidc_subject==subject,User.id!=user.id))
        if duplicate: raise ValueError('Federated identity is already bound')
        s.execute(update(User).where(User.id==user.id,User.tenant_id==tenant_id).values(
            oidc_issuer=issuer,oidc_subject=subject,token_version=User.token_version+1),
            execution_options={'synchronize_session':False})
        operator_event(s,tenant_id,'auth.oidc.bound',user.id,user.id,binding='updated')
    return True


def bind_saml_identity(engine, tenant_id, email, subject):
    """Bind a prevalidated NameID to one account; revoke previous sessions."""
    from .main import User, Audit, utc, audit_digest, AUDIT_HMAC_KEY
    tenant_id=str(uuid.UUID(tenant_id))
    if not subject or len(subject)>512: raise ValueError('Invalid SAML subject')
    with Session(engine) as s, s.begin():
        if engine.dialect.name=='postgresql':
            s.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"),{'tenant':tenant_id})
        user=s.scalar(select(User).where(User.tenant_id==tenant_id,User.email==email.strip().lower()))
        if not user: raise ValueError('Account not found')
        if s.scalar(select(User.id).where(User.tenant_id==tenant_id,User.saml_subject==subject,User.id!=user.id)):
            raise ValueError('SAML subject already assigned')
        s.execute(update(User).where(User.id==user.id,User.tenant_id==tenant_id).values(
            saml_subject=subject,token_version=User.token_version+1),
            execution_options={'synchronize_session':False})
        operator_event(s,tenant_id,'auth.saml.bound',user.id,user.id,binding='saml')
    return True

def assert_administrative_database(engine):
    """Check the connected role, not URL text that may be encoded or aliased."""
    if engine.dialect.name=='sqlite':
        return
    if engine.dialect.name!='postgresql':
        raise RuntimeError('Unsupported administrative database')
    with engine.connect() as connection:
        identity=connection.execute(text("""
            SELECT current_user, r.rolsuper, pg_get_userbyid(c.relowner)
            FROM pg_roles r JOIN pg_class c ON c.oid=to_regclass('public.users')
            WHERE r.rolname=current_user
        """)).one_or_none()
        if identity is None or identity[0]=='lexigrid_runtime' or not (
            identity[1] or identity[0]==identity[2]
        ):
            raise RuntimeError('Use a schema-owner connection for privileged administration')


def main():
    parser=argparse.ArgumentParser(description='LexiGrid privileged administration (owner DB only)')
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('create-tenant');p.add_argument('--name',required=True);p.add_argument('--email',required=True);p.add_argument('--role',choices=['tenant_admin','platform_admin'],default='tenant_admin')
    p=sub.add_parser('reset-password');p.add_argument('--tenant-id',required=True);p.add_argument('--email',required=True)
    p=sub.add_parser('bind-oidc');p.add_argument('--tenant-id',required=True);p.add_argument('--email',required=True);p.add_argument('--issuer',required=True);p.add_argument('--subject',required=True)
    p=sub.add_parser('bind-saml');p.add_argument('--tenant-id',required=True);p.add_argument('--email',required=True);p.add_argument('--subject',required=True)
    args=parser.parse_args()
    if os.getenv('LEXIGRID_ADMIN_CONFIRM')!='YES':
        parser.error('Set LEXIGRID_ADMIN_CONFIRM=YES for privileged changes')
    url=os.environ.get('DATABASE_URL','').strip()
    if not url:parser.error('Set DATABASE_URL in the approved schema-owner environment')
    engine=None
    try:
        engine=create_engine(validate_database_identity(url),pool_pre_ping=True)
        assert_administrative_database(engine)
    except (SQLAlchemyError,RuntimeError,ValueError):
        if engine is not None:engine.dispose()
        parser.error('Administrative database check failed; use a reachable migrated schema-owner connection')
    if args.command=='bind-oidc':
        bind_oidc_identity(engine,args.tenant_id,args.email,args.issuer,args.subject)
        print('Federated identity bound; previous sessions revoked')
        return
    if args.command=='bind-saml':
        bind_saml_identity(engine,args.tenant_id,args.email,args.subject)
        print('SAML identity bound; previous sessions revoked')
        return
    password=getpass.getpass('New password (minimum 16 characters): ')
    if args.command=='create-tenant':
        print('Tenant ID:',provision_tenant(engine,args.name,args.email,password,role=args.role))
    else:
        reset_password(engine,args.tenant_id,args.email,password)
        print('Password reset; previous sessions revoked')

if __name__=='__main__':main()
