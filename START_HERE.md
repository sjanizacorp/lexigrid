# LexiGrid 5.54.15 — Native Linux and PostgreSQL

Author: Shahryar Jahangir, Aniza Inc.

This distribution initializes an empty database. Keep the original installer and backup for existing deployments. Use this distribution to restore backups created from this schema.

## 1. Prepare the host and database

Use Linux with Python 3.11+, venv/pip, PostgreSQL 16, PostgreSQL client backup tools, and an approved HTTPS reverse proxy. Install distribution packages for XML security if required by the SAML dependencies. Connected installation uses the pinned requirements.txt; disconnected installations require a separately prepared, target-compatible wheelhouse. Run the application as a dedicated non-root account with a private installation directory. Do not expose PostgreSQL publicly.

Have the DBA create an empty UTF-8 database owned by a dedicated migration account. Initial migrations create the restricted lexigrid_runtime cluster role; the migration account requires role-management privileges and BYPASSRLS for privileged administrative provisioning. Keep those maintenance credentials separate from service credentials. A DBA may instead perform initial setup using a controlled administrative connection. The application must never run as that account. Use private password prompts or approved secret injection; do not put passwords into command history.

## 2. Install and migrate

Extract the archive, preserve executable permissions and enter LexiGrid. As the dedicated application account, run:

```sh
./scripts/native/install.sh --database postgres --pg-host 127.0.0.1 --pg-port 5432 --pg-database client_irm --pg-user lexigrid_owner
```

Replace host, database and owner with the DBA-provisioned values. The installer prompts privately for the database password, installs dependencies into .venv, creates private .env.native keys and upgrades the schema. It does not install PostgreSQL or create the database. Existing .env.native is retained on reinstall. A new PostgreSQL install initially contains the owner connection and must remain offline until step 4.

## 3. Create the initial platform administrator

Interactive installation offers a named organization and initial platform administrator. Record its generated password privately, change the password in Security and optionally add an authenticator there. If installation was unattended, or no administrator was created, run while the owner connection is still configured:

```sh
./lexictl admin create-tenant --name "Client organization" --email administrator@example.invalid --role platform_admin
```

Use the real administrator address. Password entry is private. Do not repeat tenant creation on an existing deployment. Later tenant administrators use the default tenant_admin role. Password recovery and identity binding require an explicit owner maintenance connection through LEXIGRID_ADMIN_DATABASE_URL; they do not overwrite the runtime configuration.

## 4. Activate restricted database access

Before any application startup, run:

```sh
.venv/bin/python -m app.provision_runtime --native-config .env.native
```

Enter a separate runtime database password of at least 24 characters. This explicit command configures lexigrid_runtime and replaces only DATABASE_URL in .env.native, retaining all original application keys. The role is cluster-wide: coordinate its credentials if multiple databases share a PostgreSQL cluster. The command refuses already-active runtime configuration. Keep the owner password in the maintenance secret store, then remove maintenance credential variables from the service environment.

Run read-only readiness diagnostics with the native runtime configuration:

```sh
.venv/bin/python - <<'PY'
import os
from scripts.native.manager import read_config
os.environ.update(read_config())
from app.diagnostics import main
main()
PY
```

Require ready=true. Diagnostic readiness covers database grants and schema, not external TLS or IdP commissioning.

## 5. Smoke test and configure services

```sh
./lexictl start
./lexictl status
curl --fail http://127.0.0.1:8000/health
./lexictl stop
```

Use the example systemd units in scripts/native/systemd. Review the installation path, service account and filesystem permissions before copying them to /etc/systemd/system. Both units load the same private .env.native and must use restricted runtime credentials. The workflow scheduler is a separate service; starting the native API does not start it. Do not run a systemd API and lexictl start concurrently. For systemd deployments use systemctl for lifecycle and inspect the API health endpoint directly.

Terminate TLS at the approved proxy, forwarding to loopback only. Configure an HTTPS hostname, certificates, request size/time limits and log retention for the intended workload. Configure both Microsoft Entra ID OIDC and AD FS SAML if required, using the Active Directory manual. Register exact callback URLs and explicitly bind existing accounts. Enforce MFA at the IdP; qualify recovery before enabling SSO for users.

## 6. Complete client acceptance

Before serving customer traffic, record results for:

- First sign-in, MFA enrollment, password rotation and revoked old sessions.
- Platform administrator tenant creation and least-privilege tenant user access; a denied foreign-tenant request.
- PDF/DOCX extraction against authorized source text and tables, reviewed draft import, editing and stale-write conflicts.
- SMTP configuration, worker processing, retry visibility and a consented test recipient.
- HTTPS and certificate validation, backups with original keys, isolated restore and expected tenant reads.
- Configured IdP, KMS/Conjur/Vault, audit retention/WORM and SIEM integrations on the actual customer infrastructure.
- Host reboot/service recovery, monitoring, capacity and disaster recovery appropriate to the deployment.

An integration is not accepted solely because settings are present. Windows hosts, external integrations, offline wheel installation and HA/failover require separate target qualification. See docs/MANUAL_INDEX.md for the detailed manuals. No compliance certification is implied.


## Dedicated PostgreSQL identities

Database identities must be explicit and separate from an operator's operating-system login. Native installation defaults to `lexigrid_owner` for privileged setup, and the application uses restricted `lexigrid_runtime` credentials after provisioning. A DBA may choose a dedicated maintenance account such as `lexiadmin` using `--pg-user lexiadmin`; create it under the deployment's approved database administration procedure. Migration-created roles use fixed product names, never the current OS username. The installer does not automatically create a personal or privileged account named after the person running it. SQLite uses a database file and has no database login.

For a supplied PostgreSQL URL, put the intended account explicitly before `@`, for example `postgresql+psycopg://lexigrid_runtime@db.example.invalid/lexigrid` (supply credentials through the approved configuration or secret mechanism). URLs such as `postgresql:///lexigrid` and URLs with `user` / `username` query overrides are rejected before a connection is attempted. Installation, application startup, maintenance, runtime provisioning, diagnostics and the backup script apply the same check. The operating-system username, PGUSER and database-service defaults cannot supply an omitted identity.

Before upgrading an existing PostgreSQL deployment with an implicit username URL, have the DBA supply the approved dedicated account explicitly. Do not rename roles, reset passwords, replace encryption keys or recreate databases simply to satisfy this setting. Existing explicit connections, original credentials and data are retained. Audit records may still identify the actual OS operator separately from the database role.
