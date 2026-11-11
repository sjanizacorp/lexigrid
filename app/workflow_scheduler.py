"""Tenant-scoped, recurring workflow SLA scanner.

Delivery claims use bounded leases shared by scheduler processes. Uses the same restricted DB role as the API.
Author: Shahryar Jahangir, Aniza Inc.
"""
import argparse
import logging
import os
import time
from datetime import date, timedelta
from types import SimpleNamespace
from sqlalchemy import func, literal, or_, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from .main import SessionLocal, Tenant, User, uid, utc
from .workflows import WorkflowRun, WorkflowNotification, WorkflowDelivery, due_step, notify
from . import notification_delivery

logger = logging.getLogger('lexigrid.workflow_scheduler')


def _set_tenant_context(session, tenant_id):
    if session.bind.dialect.name == 'postgresql':
        session.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"),
                        {'tenant': tenant_id})


def scan_tenant(session, tenant_id, today=None):
    """Persist one reminder per overdue step; caller controls the transaction."""
    today = today or date.today()
    runs = session.scalars(select(WorkflowRun).where(
        WorkflowRun.tenant_id == tenant_id, WorkflowRun.state == 'pending'
    ).order_by(WorkflowRun.id)).all()
    created = 0
    escalated = 0
    import os
    threshold = int(os.getenv('LEXIGRID_SLA_ESCALATE_DAYS', '2'))
    if threshold < 1 or threshold > 365:
        raise ValueError('LEXIGRID_SLA_ESCALATE_DAYS must be between 1 and 365')
    for run in runs:
        due = due_step(run)
        if due is None or due >= today:
            continue
        import json
        step = json.loads(run.steps_snapshot)[run.step_index]
        key = f'{run.id}:overdue:{run.step_index}:{due.isoformat()}'
        exists = session.scalar(select(WorkflowNotification.id).where(
            WorkflowNotification.tenant_id == tenant_id,
            WorkflowNotification.event_key == key,
            WorkflowNotification.recipient_id == step['approver_user_id']))
        if not exists:
            notify(session, run, step['approver_user_id'], key,
                   f'Overdue approval since {due.isoformat()}')
            created += 1
        if (today - due).days >= threshold:
            admins = session.scalars(select(User).where(User.tenant_id == tenant_id,
                User.role == 'tenant_admin', User.active == 1)).all()
            for admin in admins:
                escalation_key = f'{run.id}:escalation:{run.step_index}:{due.isoformat()}:{threshold}'
                existing = session.scalar(select(WorkflowNotification.id).where(
                    WorkflowNotification.tenant_id == tenant_id,
                    WorkflowNotification.event_key == escalation_key,
                    WorkflowNotification.recipient_id == admin.id))
                if not existing:
                    notify(session, run, admin.id, escalation_key,
                           f'SLA escalation: approval overdue since {due.isoformat()}')
                    escalated += 1
    return {'checked': len(runs), 'created': created, 'escalated': escalated}


def scan_all(session_factory=SessionLocal, today=None):
    """One transaction per tenant; PostgreSQL RLS context is local to that transaction."""
    with session_factory() as session:
        tenant_ids = session.scalars(select(Tenant.id).order_by(Tenant.id)).all()
    results = {}
    for tenant_id in tenant_ids:
        with session_factory() as session:
            _set_tenant_context(session, tenant_id)
            try:
                result = scan_tenant(session, tenant_id, today=today)
                session.commit()
                results[tenant_id] = result
            except IntegrityError:
                session.rollback()
                # A concurrent worker may have written the same unique event key.
                # Re-scan in a fresh transaction to get a consistent result.
                with session_factory() as retry:
                    _set_tenant_context(retry, tenant_id)
                    results[tenant_id] = scan_tenant(retry, tenant_id, today=today)
                    retry.commit()
    return results


def main():
    parser = argparse.ArgumentParser(description='LexiGrid workflow overdue notification scheduler')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    parser.add_argument('--interval-seconds', type=int,
                        default=int(os.getenv('LEXIGRID_WORKFLOW_SCAN_SECONDS', '300')))
    args = parser.parse_args()
    if not 30 <= args.interval_seconds <= 86400:
        parser.error('interval-seconds must be between 30 and 86400')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    while True:
        try:
            results = scan_all()
            delivery_results = deliver_all()
            logger.info('Workflow scan completed: tenants=%d notifications=%d delivered=%d failed=%d',
                        len(results), sum(r['created'] for r in results.values()),
                        sum(r['delivered'] for r in delivery_results.values()),
                        sum(r['failed'] for r in delivery_results.values()))
        except Exception:
            logger.exception('Workflow scan failed')
            if args.once:
                raise
        if args.once:
            break
        time.sleep(args.interval_seconds)


MAX_DELIVERY_ATTEMPTS = 5


def _seed_deliveries(session, tenant_id, channels):
    insert = pg_insert if session.bind.dialect.name == 'postgresql' else sqlite_insert
    for channel in channels:
        sent_at = getattr(WorkflowNotification, channel + '_sent_at')
        source = select(
            WorkflowNotification.id, literal(channel), WorkflowNotification.tenant_id,
            literal('queued'), literal(0), literal(utc()),
        ).join(User, (User.id == WorkflowNotification.recipient_id)
               & (User.tenant_id == WorkflowNotification.tenant_id)).where(
            WorkflowNotification.tenant_id == tenant_id, User.active == 1, sent_at.is_(None))
        statement = insert(WorkflowDelivery).from_select(
            ['notification_id','channel','tenant_id','status','attempts','next_attempt_at'],
            source, include_defaults=False,
        ).on_conflict_do_nothing(index_elements=['notification_id','channel'])
        session.execute(statement)
        # Reconcile timestamps written by an older scheduler during a rolling update.
        completed = select(WorkflowNotification.id).where(
            WorkflowNotification.tenant_id == tenant_id, sent_at.is_not(None))
        timestamp = select(sent_at).where(
            WorkflowNotification.id == WorkflowDelivery.notification_id,
            WorkflowNotification.tenant_id == tenant_id).scalar_subquery()
        session.execute(update(WorkflowDelivery).where(
            WorkflowDelivery.tenant_id == tenant_id, WorkflowDelivery.channel == channel,
            WorkflowDelivery.status != 'delivered', WorkflowDelivery.notification_id.in_(completed),
        ).values(status='delivered',delivered_at=timestamp,lease_token=None,last_error=None))


def _claim_delivery(session, tenant_id, channels):
    now = utc()
    scope = (WorkflowDelivery.tenant_id == tenant_id, WorkflowDelivery.channel.in_(channels))
    session.execute(update(WorkflowDelivery).where(
        *scope, WorkflowDelivery.status == 'sending',
        WorkflowDelivery.next_attempt_at <= now,
        WorkflowDelivery.attempts >= MAX_DELIVERY_ATTEMPTS,
    ).values(status='failed',lease_token=None,last_error='DeliveryLeaseExpired'))
    eligible = (
        (WorkflowDelivery.status.in_(['queued','retry','sending'])
         & (WorkflowDelivery.attempts < MAX_DELIVERY_ATTEMPTS))
        | (WorkflowDelivery.status == 'retry_requested')
    ) & (WorkflowDelivery.next_attempt_at <= now)
    candidates = select(WorkflowDelivery.notification_id, WorkflowDelivery.channel).join(
        WorkflowNotification,
        (WorkflowNotification.id == WorkflowDelivery.notification_id)
        & (WorkflowNotification.tenant_id == WorkflowDelivery.tenant_id),
    ).join(User, (User.id == WorkflowNotification.recipient_id)
           & (User.tenant_id == WorkflowNotification.tenant_id)).where(
        *scope, eligible, User.active == 1,
    ).order_by(WorkflowDelivery.next_attempt_at, WorkflowDelivery.notification_id,
               WorkflowDelivery.channel).limit(1)
    if session.bind.dialect.name == 'postgresql':
        # Materialize once: a correlated IN subquery can be re-evaluated after
        # each updated row, selecting additional eligible channels.
        claimed = candidates.with_for_update(skip_locked=True, of=WorkflowDelivery).cte(
            'workflow_delivery_candidate').prefix_with('MATERIALIZED')
        candidates = select(claimed.c.notification_id, claimed.c.channel)
    return session.execute(update(WorkflowDelivery).where(
        *scope, eligible,
        tuple_(WorkflowDelivery.notification_id,WorkflowDelivery.channel).in_(candidates),
    ).values(status='sending', attempts=WorkflowDelivery.attempts+1,
             next_attempt_at=now+timedelta(minutes=10), lease_token=uid())
      .returning(WorkflowDelivery.notification_id,WorkflowDelivery.channel,
                 WorkflowDelivery.attempts,WorkflowDelivery.lease_token)).one_or_none()


def _finish_delivery(session, tenant_id, claim, error_type=None):
    notification_id, channel, attempts, token = claim
    now = utc()
    values = {'lease_token':None,'last_error':error_type}
    if error_type is None:
        values.update(status='delivered',delivered_at=now)
    else:
        values.update(status='failed' if attempts >= MAX_DELIVERY_ATTEMPTS else 'retry',
                      next_attempt_at=now+timedelta(minutes=min(60,2**attempts)))
    written = session.scalar(update(WorkflowDelivery).where(
        WorkflowDelivery.tenant_id == tenant_id,
        WorkflowDelivery.notification_id == notification_id, WorkflowDelivery.channel == channel,
        WorkflowDelivery.status == 'sending', WorkflowDelivery.attempts == attempts,
        WorkflowDelivery.lease_token == token,
    ).values(**values).returning(WorkflowDelivery.notification_id))
    if written is not None and error_type is None:
        timestamp = getattr(WorkflowNotification,channel+'_sent_at')
        session.execute(update(WorkflowNotification).where(
            WorkflowNotification.id == notification_id,
            WorkflowNotification.tenant_id == tenant_id,
        ).values({timestamp:func.coalesce(timestamp,now)}))
    return written is not None


def deliver_tenant(session, tenant_id, limit=100):
    """Lease and deliver each enabled channel with bounded retries."""
    enabled = notification_delivery.channels()
    if not enabled:
        return {'delivered':0,'failed':0}
    _set_tenant_context(session,tenant_id)
    _seed_deliveries(session,tenant_id,enabled)
    session.commit()
    delivered = failed = 0
    for _ in range(limit * len(enabled)):
        _set_tenant_context(session,tenant_id)
        claim = _claim_delivery(session,tenant_id,enabled)
        session.commit()
        if claim is None:
            break
        _set_tenant_context(session,tenant_id)
        notification_id,channel,_,_ = claim
        row = session.execute(select(WorkflowNotification,User.email).join(
            User,(User.id == WorkflowNotification.recipient_id)
            & (User.tenant_id == WorkflowNotification.tenant_id)).where(
                WorkflowNotification.id == notification_id,
                WorkflowNotification.tenant_id == tenant_id,User.active == 1)).one_or_none()
        payload = SimpleNamespace(**{
            name:getattr(row[0],name) for name in ('id','event_key','message','run_id')
        }) if row else None
        email = row[1] if row else None
        session.commit()
        error_type = None
        try:
            if payload is None:
                raise ValueError('Recipient unavailable')
            getattr(notification_delivery,'send_'+channel)(payload,email)
        except Exception as exc:
            error_type = type(exc).__name__
            logger.warning('Notification delivery failed: notification_id=%s channel=%s error_type=%s',
                           notification_id,channel,error_type)
        _set_tenant_context(session,tenant_id)
        if _finish_delivery(session,tenant_id,claim,error_type):
            delivered += int(error_type is None)
            failed += int(error_type is not None)
        session.commit()
    return {'delivered':delivered,'failed':failed}


def deliver_all(session_factory=SessionLocal):
    with session_factory() as session:
        tenant_ids = session.scalars(select(Tenant.id).order_by(Tenant.id)).all()
    result = {}
    for tenant_id in tenant_ids:
        with session_factory() as session:
            _set_tenant_context(session, tenant_id)
            result[tenant_id] = deliver_tenant(session, tenant_id)
    return result


if __name__ == '__main__':
    main()
