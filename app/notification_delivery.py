"""Outbound notification delivery; fixed operator-configured destinations only.
Author: Shahryar Jahangir, Aniza Inc.
"""
import json
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage
from urllib.parse import urlsplit


def channels():
    return [c for c in ('webhook', 'email') if os.getenv('LEXIGRID_NOTIFY_'+c.upper()+'_ENABLED') == '1']


def send_webhook(notification, recipient_email):
    url = os.getenv('LEXIGRID_NOTIFY_WEBHOOK_URL', '')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Webhook destination must be a configured HTTPS URL without credentials or fragment')
    # Destination is supplied by the administrator, not by tenant/user content.
    body = json.dumps({'event_id': notification.event_key, 'notification_id': notification.id,
                       'recipient': recipient_email, 'message': notification.message,
                       'run_id': notification.run_id}, sort_keys=True).encode()
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'Content-Type': 'application/json', 'Idempotency-Key': notification.id,
        'User-Agent': 'LexiGrid-Notifications/1'})
    with urllib.request.urlopen(req, timeout=8, context=ssl.create_default_context()) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError('Webhook delivery rejected')


def send_smtp(config, recipients, message, *, timeout=15):
    context = ssl.create_default_context()
    if config.security == 'ssl':
        client = smtplib.SMTP_SSL(config.host, config.port, timeout=timeout, context=context)
    else:
        client = smtplib.SMTP(config.host, config.port, timeout=timeout)
    refused = None
    try:
        with client as smtp:
            if config.security == 'starttls':
                smtp.starttls(context=context)
            if config.username:
                smtp.login(config.username, config.password)
            payload = message.as_bytes(policy=message.policy.clone(linesep="\r\n"))
            refused = smtp.sendmail(config.sender, recipients, payload)
    except (smtplib.SMTPException, OSError):
        if refused is None:
            raise
        # A failed SMTP QUIT does not undo an acknowledged DATA command.
    return refused


def send_email(notification, recipient_email):
    from .mail_configuration import require_smtp
    cfg=require_smtp()
    if not recipient_email or '\n' in recipient_email or '\r' in recipient_email:
        raise ValueError('Invalid recipient address')
    msg=EmailMessage()
    msg['From']=cfg.sender
    msg['To']=recipient_email
    msg['Subject']='LexiGrid workflow notification'
    msg['Message-ID']=f'<{notification.id}@lexigrid.local>'
    msg.set_content(notification.message+'\nWorkflow ID: '+notification.run_id)
    refused = send_smtp(cfg, [recipient_email], msg, timeout=8)
    if refused:
        raise smtplib.SMTPRecipientsRefused(refused)
