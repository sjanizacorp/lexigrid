CREATE TABLE public.approvals (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    object_type character varying(20) NOT NULL,
    object_id character varying(36) NOT NULL,
    reason text NOT NULL,
    requester_id character varying(36) NOT NULL,
    approver_id character varying(36),
    decision_note text,
    state character varying(20) NOT NULL,
    version integer NOT NULL,
    target_version integer,
    created_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone
);

ALTER TABLE ONLY public.approvals FORCE ROW LEVEL SECURITY;

CREATE TABLE public.audit (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    at timestamp with time zone NOT NULL,
    actor_id character varying(36) NOT NULL,
    action character varying(80) NOT NULL,
    object_id character varying(36) NOT NULL,
    details text NOT NULL,
    integrity_mac character varying(64)
);

ALTER TABLE ONLY public.audit FORCE ROW LEVEL SECURITY;

CREATE TABLE public.business_services (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    name character varying(200) NOT NULL,
    owner character varying(200) NOT NULL,
    criticality character varying(20) NOT NULL,
    recovery_time_hours integer NOT NULL,
    recovery_point_hours integer NOT NULL
);

ALTER TABLE ONLY public.business_services FORCE ROW LEVEL SECURITY;

CREATE TABLE public.control_findings (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    control_id character varying(36) NOT NULL,
    title character varying(200) NOT NULL,
    severity character varying(20) NOT NULL,
    remediation text NOT NULL,
    status character varying(20) NOT NULL
);

ALTER TABLE ONLY public.control_findings FORCE ROW LEVEL SECURITY;

CREATE TABLE public.control_links (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    control_id character varying(36) NOT NULL,
    risk_id character varying(36),
    requirement_id character varying(36)
);

ALTER TABLE ONLY public.control_links FORCE ROW LEVEL SECURITY;

CREATE TABLE public.control_tests (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    control_id character varying(36) NOT NULL,
    result character varying(25) NOT NULL,
    procedure text NOT NULL,
    notes text NOT NULL,
    tester_id character varying(36) NOT NULL,
    tested_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.control_tests FORCE ROW LEVEL SECURITY;

CREATE TABLE public.controls (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    code character varying(60) NOT NULL,
    title character varying(200) NOT NULL,
    description text NOT NULL,
    owner character varying(200) NOT NULL,
    status character varying(30) NOT NULL,
    version integer NOT NULL
);

ALTER TABLE ONLY public.controls FORCE ROW LEVEL SECURITY;

CREATE TABLE public.enterprise_records (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    kind character varying(50) NOT NULL,
    title character varying(200) NOT NULL,
    state character varying(40) NOT NULL,
    owner character varying(200) NOT NULL,
    data text NOT NULL,
    version integer NOT NULL,
    created_by character varying(36) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.enterprise_records FORCE ROW LEVEL SECURITY;

CREATE TABLE public.enterprise_relations (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    source_id character varying(36) NOT NULL,
    target_id character varying(36) NOT NULL,
    relation character varying(40) NOT NULL
);

ALTER TABLE ONLY public.enterprise_relations FORCE ROW LEVEL SECURITY;

CREATE TABLE public.evidence (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    control_id character varying(36) NOT NULL,
    title character varying(200) NOT NULL,
    uri text NOT NULL,
    sha256 character varying(64) NOT NULL,
    submitted_by character varying(36) NOT NULL,
    submitted_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.evidence FORCE ROW LEVEL SECURITY;

CREATE TABLE public.evidence_blobs (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    control_id character varying(36) NOT NULL,
    filename character varying(200) NOT NULL,
    content_type character varying(100) NOT NULL,
    sha256 character varying(64) NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    submitted_by character varying(36) NOT NULL,
    submitted_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.evidence_blobs FORCE ROW LEVEL SECURITY;

CREATE TABLE public.frameworks (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    name character varying(200) NOT NULL,
    revision character varying(80) NOT NULL
);

ALTER TABLE ONLY public.frameworks FORCE ROW LEVEL SECURITY;

CREATE TABLE public.login_throttles (
    key_hash character varying(64) NOT NULL,
    window_start bigint NOT NULL,
    attempts integer NOT NULL
);

CREATE TABLE public.loss_events (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    service_id character varying(36) NOT NULL,
    risk_id character varying(36),
    title character varying(200) NOT NULL,
    occurred_on character varying(10) NOT NULL,
    loss_cents integer NOT NULL,
    description text NOT NULL,
    created_by character varying(36) NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.loss_events FORCE ROW LEVEL SECURITY;

CREATE TABLE public.mail_runtime_settings (
    id integer NOT NULL,
    encrypted_payload text NOT NULL,
    revision integer NOT NULL
);

CREATE SEQUENCE public.mail_runtime_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.mail_runtime_settings_id_seq OWNED BY public.mail_runtime_settings.id;

CREATE TABLE public.policies (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    code character varying(60) NOT NULL,
    title character varying(200) NOT NULL,
    body text NOT NULL,
    owner character varying(200) NOT NULL,
    status character varying(20) NOT NULL,
    version integer NOT NULL
);

ALTER TABLE ONLY public.policies FORCE ROW LEVEL SECURITY;

CREATE TABLE public.remediations (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    finding_id character varying(36) NOT NULL,
    description text NOT NULL,
    owner character varying(200) NOT NULL,
    due_date character varying(10) NOT NULL,
    state character varying(20) NOT NULL,
    closure_note text,
    version integer NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.remediations FORCE ROW LEVEL SECURITY;

CREATE TABLE public.requirements (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    framework_id character varying(36) NOT NULL,
    reference character varying(120) NOT NULL,
    text text NOT NULL
);

ALTER TABLE ONLY public.requirements FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_assessments (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    risk_id character varying(36) NOT NULL,
    kind character varying(20) NOT NULL,
    likelihood integer NOT NULL,
    impact integer NOT NULL,
    rationale text NOT NULL,
    assessor_id character varying(36) NOT NULL,
    assessed_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.risk_assessments FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_comments (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    risk_id character varying(36) NOT NULL,
    author_id character varying(36) NOT NULL,
    body text NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.risk_comments FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_contacts (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    risk_id character varying(36) NOT NULL,
    email character varying(320) NOT NULL,
    role character varying(30) NOT NULL,
    notify integer NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.risk_contacts FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_links (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    source_id character varying(36) NOT NULL,
    target_id character varying(36) NOT NULL,
    relation character varying(30) NOT NULL
);

ALTER TABLE ONLY public.risk_links FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_mail (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    risk_id character varying(36) NOT NULL,
    email character varying(320) NOT NULL,
    kind character varying(32) NOT NULL,
    subject character varying(255) NOT NULL,
    content text NOT NULL,
    status character varying(30) NOT NULL,
    attempts integer NOT NULL,
    due_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    sent_at timestamp with time zone,
    delivered_at timestamp with time zone,
    read_at timestamp with time zone,
    receipt_hash character varying(64) NOT NULL,
    provider_message_id character varying(255),
    last_error character varying(100)
);

ALTER TABLE ONLY public.risk_mail FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_mail_settings (
    tenant_id character varying(36) NOT NULL,
    auto_email integer NOT NULL
);

ALTER TABLE ONLY public.risk_mail_settings FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_reminders (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    risk_id character varying(36) NOT NULL,
    enabled integer NOT NULL,
    interval_days integer NOT NULL,
    next_due timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.risk_reminders FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risk_treatments (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    risk_id character varying(36) NOT NULL,
    strategy character varying(20) NOT NULL,
    description text NOT NULL,
    owner character varying(200) NOT NULL,
    due_date character varying(10) NOT NULL,
    status character varying(20) NOT NULL,
    version integer NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.risk_treatments FORCE ROW LEVEL SECURITY;

CREATE TABLE public.risks (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    title character varying(200) NOT NULL,
    description text NOT NULL,
    category character varying(100) NOT NULL,
    owner character varying(200) NOT NULL,
    likelihood integer NOT NULL,
    impact integer NOT NULL,
    status character varying(20) NOT NULL,
    version integer NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.risks FORCE ROW LEVEL SECURITY;

CREATE TABLE public.saml_replays (
    id character varying(512) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.saml_replays FORCE ROW LEVEL SECURITY;

CREATE TABLE public.service_dependencies (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    service_id character varying(36) NOT NULL,
    vendor_id character varying(36),
    risk_id character varying(36)
);

ALTER TABLE ONLY public.service_dependencies FORCE ROW LEVEL SECURITY;

CREATE TABLE public.tenants (
    id character varying(36) NOT NULL,
    name character varying(200) NOT NULL
);

CREATE TABLE public.users (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    email character varying(320) NOT NULL,
    password_hash text NOT NULL,
    role character varying(30) NOT NULL,
    active integer NOT NULL,
    token_version integer NOT NULL,
    saml_subject character varying(512),
    oidc_issuer character varying(512),
    oidc_subject character varying(512),
    mfa_secret text,
    mfa_pending text,
    mfa_last_counter integer NOT NULL
);

ALTER TABLE ONLY public.users FORCE ROW LEVEL SECURITY;

CREATE TABLE public.vendor_assessments (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    vendor_id character varying(36) NOT NULL,
    assessed_by character varying(36) NOT NULL,
    security_score integer NOT NULL,
    privacy_score integer NOT NULL,
    resilience_score integer NOT NULL,
    findings text NOT NULL,
    assessed_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.vendor_assessments FORCE ROW LEVEL SECURITY;

CREATE TABLE public.vendors (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    name character varying(200) NOT NULL,
    service character varying(300) NOT NULL,
    criticality character varying(20) NOT NULL,
    owner character varying(200) NOT NULL,
    status character varying(20) NOT NULL,
    version integer NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.vendors FORCE ROW LEVEL SECURITY;

CREATE TABLE public.workflow_decisions (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    run_id character varying(36) NOT NULL,
    step_index integer NOT NULL,
    actor_id character varying(36) NOT NULL,
    decision character varying(20) NOT NULL,
    note text NOT NULL,
    at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.workflow_decisions FORCE ROW LEVEL SECURITY;

CREATE TABLE public.workflow_deliveries (
    notification_id character varying(36) NOT NULL,
    channel character varying(10) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    status character varying(24) NOT NULL,
    attempts integer NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    lease_token character varying(36),
    last_error character varying(100),
    delivered_at timestamp with time zone,
    CONSTRAINT ck_workflow_delivery_attempts CHECK ((attempts >= 0)),
    CONSTRAINT ck_workflow_delivery_channel CHECK (((channel)::text = ANY ((ARRAY['webhook'::character varying, 'email'::character varying])::text[])))
);

ALTER TABLE ONLY public.workflow_deliveries FORCE ROW LEVEL SECURITY;

CREATE TABLE public.workflow_notifications (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    recipient_id character varying(36) NOT NULL,
    run_id character varying(36) NOT NULL,
    event_key character varying(160) NOT NULL,
    message character varying(500) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    read_at timestamp with time zone,
    webhook_sent_at timestamp with time zone,
    email_sent_at timestamp with time zone
);

ALTER TABLE ONLY public.workflow_notifications FORCE ROW LEVEL SECURITY;

CREATE TABLE public.workflow_runs (
    id character varying(36) NOT NULL,
    tenant_id character varying(36) NOT NULL,
    definition_id character varying(36) NOT NULL,
    object_id character varying(36) NOT NULL,
    initiated_by character varying(36) NOT NULL,
    state character varying(20) NOT NULL,
    step_index integer NOT NULL,
    version integer NOT NULL,
    steps_snapshot text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone,
    target_state character varying(40),
    consumed_at timestamp with time zone,
    object_version integer,
    object_digest character varying(64)
);

ALTER TABLE ONLY public.workflow_runs FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY public.mail_runtime_settings ALTER COLUMN id SET DEFAULT nextval('public.mail_runtime_settings_id_seq'::regclass);

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit
    ADD CONSTRAINT audit_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.business_services
    ADD CONSTRAINT business_services_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.business_services
    ADD CONSTRAINT business_services_tenant_id_name_key UNIQUE (tenant_id, name);

ALTER TABLE ONLY public.control_findings
    ADD CONSTRAINT control_findings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_links
    ADD CONSTRAINT control_links_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_tests
    ADD CONSTRAINT control_tests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.controls
    ADD CONSTRAINT controls_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.controls
    ADD CONSTRAINT controls_tenant_id_code_key UNIQUE (tenant_id, code);

ALTER TABLE ONLY public.enterprise_records
    ADD CONSTRAINT enterprise_records_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.enterprise_relations
    ADD CONSTRAINT enterprise_relations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.enterprise_relations
    ADD CONSTRAINT enterprise_relations_tenant_id_source_id_target_id_relation_key UNIQUE (tenant_id, source_id, target_id, relation);

ALTER TABLE ONLY public.evidence_blobs
    ADD CONSTRAINT evidence_blobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.frameworks
    ADD CONSTRAINT frameworks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.frameworks
    ADD CONSTRAINT frameworks_tenant_id_name_revision_key UNIQUE (tenant_id, name, revision);

ALTER TABLE ONLY public.login_throttles
    ADD CONSTRAINT login_throttles_pkey PRIMARY KEY (key_hash);

ALTER TABLE ONLY public.loss_events
    ADD CONSTRAINT loss_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.mail_runtime_settings
    ADD CONSTRAINT mail_runtime_settings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_tenant_id_code_key UNIQUE (tenant_id, code);

ALTER TABLE ONLY public.remediations
    ADD CONSTRAINT remediations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.requirements
    ADD CONSTRAINT requirements_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.requirements
    ADD CONSTRAINT requirements_tenant_id_framework_id_reference_key UNIQUE (tenant_id, framework_id, reference);

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risk_comments
    ADD CONSTRAINT risk_comments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risk_contacts
    ADD CONSTRAINT risk_contacts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risk_contacts
    ADD CONSTRAINT risk_contacts_tenant_id_risk_id_email_role_key UNIQUE (tenant_id, risk_id, email, role);

ALTER TABLE ONLY public.risk_links
    ADD CONSTRAINT risk_links_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risk_links
    ADD CONSTRAINT risk_links_tenant_id_source_id_target_id_relation_key UNIQUE (tenant_id, source_id, target_id, relation);

ALTER TABLE ONLY public.risk_mail
    ADD CONSTRAINT risk_mail_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risk_mail_settings
    ADD CONSTRAINT risk_mail_settings_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY public.risk_reminders
    ADD CONSTRAINT risk_reminders_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risk_treatments
    ADD CONSTRAINT risk_treatments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risks
    ADD CONSTRAINT risks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.saml_replays
    ADD CONSTRAINT saml_replays_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.service_dependencies
    ADD CONSTRAINT service_dependencies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.service_dependencies
    ADD CONSTRAINT service_dependencies_tenant_id_service_id_vendor_id_risk_id_key UNIQUE (tenant_id, service_id, vendor_id, risk_id);

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_name_key UNIQUE (name);

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workflow_notifications
    ADD CONSTRAINT uq_workflow_notification_event UNIQUE (tenant_id, event_key, recipient_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_tenant_id_email_key UNIQUE (tenant_id, email);

ALTER TABLE ONLY public.vendor_assessments
    ADD CONSTRAINT vendor_assessments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.vendors
    ADD CONSTRAINT vendors_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.vendors
    ADD CONSTRAINT vendors_tenant_id_name_key UNIQUE (tenant_id, name);

ALTER TABLE ONLY public.workflow_decisions
    ADD CONSTRAINT workflow_decisions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workflow_deliveries
    ADD CONSTRAINT workflow_deliveries_pkey PRIMARY KEY (notification_id, channel);

ALTER TABLE ONLY public.workflow_notifications
    ADD CONSTRAINT workflow_notifications_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_pkey PRIMARY KEY (id);

CREATE INDEX ix_approvals_object_id ON public.approvals USING btree (object_id);

CREATE INDEX ix_approvals_tenant_id ON public.approvals USING btree (tenant_id);

CREATE INDEX ix_audit_tenant_id ON public.audit USING btree (tenant_id);

CREATE INDEX ix_business_services_tenant_id ON public.business_services USING btree (tenant_id);

CREATE INDEX ix_control_findings_tenant_id ON public.control_findings USING btree (tenant_id);

CREATE INDEX ix_control_links_tenant_id ON public.control_links USING btree (tenant_id);

CREATE INDEX ix_control_tests_tenant_id ON public.control_tests USING btree (tenant_id);

CREATE INDEX ix_controls_tenant_id ON public.controls USING btree (tenant_id);

CREATE INDEX ix_enterprise_records_kind ON public.enterprise_records USING btree (kind);

CREATE INDEX ix_enterprise_records_tenant_id ON public.enterprise_records USING btree (tenant_id);

CREATE INDEX ix_enterprise_relations_tenant_id ON public.enterprise_relations USING btree (tenant_id);

CREATE INDEX ix_evidence_blobs_tenant_id ON public.evidence_blobs USING btree (tenant_id);

CREATE INDEX ix_evidence_tenant_id ON public.evidence USING btree (tenant_id);

CREATE INDEX ix_frameworks_tenant_id ON public.frameworks USING btree (tenant_id);

CREATE INDEX ix_loss_events_service_id ON public.loss_events USING btree (service_id);

CREATE INDEX ix_loss_events_tenant_id ON public.loss_events USING btree (tenant_id);

CREATE INDEX ix_policies_tenant_id ON public.policies USING btree (tenant_id);

CREATE INDEX ix_remediations_finding_id ON public.remediations USING btree (finding_id);

CREATE INDEX ix_remediations_tenant_id ON public.remediations USING btree (tenant_id);

CREATE INDEX ix_requirements_tenant_id ON public.requirements USING btree (tenant_id);

CREATE INDEX ix_risk_assessments_risk_id ON public.risk_assessments USING btree (risk_id);

CREATE INDEX ix_risk_assessments_tenant_id ON public.risk_assessments USING btree (tenant_id);

CREATE INDEX ix_risk_comments_risk_id ON public.risk_comments USING btree (risk_id);

CREATE INDEX ix_risk_comments_tenant_id ON public.risk_comments USING btree (tenant_id);

CREATE INDEX ix_risk_contacts_risk_id ON public.risk_contacts USING btree (risk_id);

CREATE INDEX ix_risk_contacts_tenant_id ON public.risk_contacts USING btree (tenant_id);

CREATE INDEX ix_risk_links_tenant_id ON public.risk_links USING btree (tenant_id);

CREATE INDEX ix_risk_mail_risk_id ON public.risk_mail USING btree (risk_id);

CREATE INDEX ix_risk_mail_tenant_id ON public.risk_mail USING btree (tenant_id);

CREATE INDEX ix_risk_reminders_risk_id ON public.risk_reminders USING btree (risk_id);

CREATE INDEX ix_risk_reminders_tenant_id ON public.risk_reminders USING btree (tenant_id);

CREATE INDEX ix_risk_treatments_risk_id ON public.risk_treatments USING btree (risk_id);

CREATE INDEX ix_risk_treatments_tenant_id ON public.risk_treatments USING btree (tenant_id);

CREATE INDEX ix_risks_tenant_id ON public.risks USING btree (tenant_id);

CREATE INDEX ix_service_dependencies_service_id ON public.service_dependencies USING btree (service_id);

CREATE INDEX ix_service_dependencies_tenant_id ON public.service_dependencies USING btree (tenant_id);

CREATE UNIQUE INDEX ix_users_oidc_identity ON public.users USING btree (tenant_id, oidc_issuer, oidc_subject);

CREATE INDEX ix_users_tenant_id ON public.users USING btree (tenant_id);

CREATE INDEX ix_vendor_assessments_tenant_id ON public.vendor_assessments USING btree (tenant_id);

CREATE INDEX ix_vendor_assessments_vendor_id ON public.vendor_assessments USING btree (vendor_id);

CREATE INDEX ix_vendors_tenant_id ON public.vendors USING btree (tenant_id);

CREATE INDEX ix_workflow_decisions_run_id ON public.workflow_decisions USING btree (run_id);

CREATE INDEX ix_workflow_decisions_tenant_id ON public.workflow_decisions USING btree (tenant_id);

CREATE INDEX ix_workflow_deliveries_tenant_id ON public.workflow_deliveries USING btree (tenant_id);

CREATE INDEX ix_workflow_notifications_recipient_id ON public.workflow_notifications USING btree (recipient_id);

CREATE INDEX ix_workflow_notifications_tenant_id ON public.workflow_notifications USING btree (tenant_id);

CREATE INDEX ix_workflow_runs_tenant_id ON public.workflow_runs USING btree (tenant_id);

CREATE UNIQUE INDEX uq_risk_reminders_tenant_risk ON public.risk_reminders USING btree (tenant_id, risk_id);

CREATE UNIQUE INDEX uq_workflow_notification_id_tenant ON public.workflow_notifications USING btree (id, tenant_id);

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.audit
    ADD CONSTRAINT audit_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.business_services
    ADD CONSTRAINT business_services_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.control_findings
    ADD CONSTRAINT control_findings_control_id_fkey FOREIGN KEY (control_id) REFERENCES public.controls(id);

ALTER TABLE ONLY public.control_findings
    ADD CONSTRAINT control_findings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.control_links
    ADD CONSTRAINT control_links_control_id_fkey FOREIGN KEY (control_id) REFERENCES public.controls(id);

ALTER TABLE ONLY public.control_links
    ADD CONSTRAINT control_links_requirement_id_fkey FOREIGN KEY (requirement_id) REFERENCES public.requirements(id);

ALTER TABLE ONLY public.control_links
    ADD CONSTRAINT control_links_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.control_links
    ADD CONSTRAINT control_links_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.control_tests
    ADD CONSTRAINT control_tests_control_id_fkey FOREIGN KEY (control_id) REFERENCES public.controls(id);

ALTER TABLE ONLY public.control_tests
    ADD CONSTRAINT control_tests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.controls
    ADD CONSTRAINT controls_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.enterprise_records
    ADD CONSTRAINT enterprise_records_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.enterprise_relations
    ADD CONSTRAINT enterprise_relations_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.enterprise_records(id);

ALTER TABLE ONLY public.enterprise_relations
    ADD CONSTRAINT enterprise_relations_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.enterprise_records(id);

ALTER TABLE ONLY public.enterprise_relations
    ADD CONSTRAINT enterprise_relations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.evidence_blobs
    ADD CONSTRAINT evidence_blobs_control_id_fkey FOREIGN KEY (control_id) REFERENCES public.controls(id);

ALTER TABLE ONLY public.evidence_blobs
    ADD CONSTRAINT evidence_blobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_control_id_fkey FOREIGN KEY (control_id) REFERENCES public.controls(id);

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.frameworks
    ADD CONSTRAINT frameworks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.loss_events
    ADD CONSTRAINT loss_events_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.loss_events
    ADD CONSTRAINT loss_events_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.business_services(id);

ALTER TABLE ONLY public.loss_events
    ADD CONSTRAINT loss_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.remediations
    ADD CONSTRAINT remediations_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.control_findings(id);

ALTER TABLE ONLY public.remediations
    ADD CONSTRAINT remediations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.requirements
    ADD CONSTRAINT requirements_framework_id_fkey FOREIGN KEY (framework_id) REFERENCES public.frameworks(id);

ALTER TABLE ONLY public.requirements
    ADD CONSTRAINT requirements_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_assessments
    ADD CONSTRAINT risk_assessments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_comments
    ADD CONSTRAINT risk_comments_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_comments
    ADD CONSTRAINT risk_comments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_contacts
    ADD CONSTRAINT risk_contacts_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_contacts
    ADD CONSTRAINT risk_contacts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_links
    ADD CONSTRAINT risk_links_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_links
    ADD CONSTRAINT risk_links_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_links
    ADD CONSTRAINT risk_links_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_mail
    ADD CONSTRAINT risk_mail_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_mail_settings
    ADD CONSTRAINT risk_mail_settings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_mail
    ADD CONSTRAINT risk_mail_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_reminders
    ADD CONSTRAINT risk_reminders_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_reminders
    ADD CONSTRAINT risk_reminders_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risk_treatments
    ADD CONSTRAINT risk_treatments_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.risk_treatments
    ADD CONSTRAINT risk_treatments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.risks
    ADD CONSTRAINT risks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.service_dependencies
    ADD CONSTRAINT service_dependencies_risk_id_fkey FOREIGN KEY (risk_id) REFERENCES public.risks(id);

ALTER TABLE ONLY public.service_dependencies
    ADD CONSTRAINT service_dependencies_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.business_services(id);

ALTER TABLE ONLY public.service_dependencies
    ADD CONSTRAINT service_dependencies_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.service_dependencies
    ADD CONSTRAINT service_dependencies_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.vendor_assessments
    ADD CONSTRAINT vendor_assessments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.vendor_assessments
    ADD CONSTRAINT vendor_assessments_vendor_id_fkey FOREIGN KEY (vendor_id) REFERENCES public.vendors(id);

ALTER TABLE ONLY public.vendors
    ADD CONSTRAINT vendors_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.workflow_decisions
    ADD CONSTRAINT workflow_decisions_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.workflow_decisions
    ADD CONSTRAINT workflow_decisions_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.workflow_runs(id);

ALTER TABLE ONLY public.workflow_decisions
    ADD CONSTRAINT workflow_decisions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.workflow_deliveries
    ADD CONSTRAINT workflow_deliveries_notification_id_tenant_id_fkey FOREIGN KEY (notification_id, tenant_id) REFERENCES public.workflow_notifications(id, tenant_id);

ALTER TABLE ONLY public.workflow_deliveries
    ADD CONSTRAINT workflow_deliveries_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.workflow_notifications
    ADD CONSTRAINT workflow_notifications_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.workflow_notifications
    ADD CONSTRAINT workflow_notifications_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.workflow_runs(id);

ALTER TABLE ONLY public.workflow_notifications
    ADD CONSTRAINT workflow_notifications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_definition_id_fkey FOREIGN KEY (definition_id) REFERENCES public.enterprise_records(id);

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_initiated_by_fkey FOREIGN KEY (initiated_by) REFERENCES public.users(id);

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_object_id_fkey FOREIGN KEY (object_id) REFERENCES public.enterprise_records(id);

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE public.approvals ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.audit ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.business_services ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.control_findings ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.control_links ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.control_tests ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.controls ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.enterprise_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY enterprise_records_tenant_policy ON public.enterprise_records USING (((tenant_id)::text = current_setting('app.tenant_id'::text, true))) WITH CHECK (((tenant_id)::text = current_setting('app.tenant_id'::text, true)));

ALTER TABLE public.enterprise_relations ENABLE ROW LEVEL SECURITY;

CREATE POLICY enterprise_relations_tenant_policy ON public.enterprise_relations USING (((tenant_id)::text = current_setting('app.tenant_id'::text, true))) WITH CHECK (((tenant_id)::text = current_setting('app.tenant_id'::text, true)));

ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.evidence_blobs ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.frameworks ENABLE ROW LEVEL SECURITY;

CREATE POLICY lexigrid_tenant_isolation ON public.approvals USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.audit USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.business_services USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.control_findings USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.control_links USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.control_tests USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.controls USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.evidence USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.evidence_blobs USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.frameworks USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.loss_events USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.policies USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.remediations USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.requirements USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_assessments USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_comments USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_contacts USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_links USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_mail USING (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text))) WITH CHECK (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text)));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_mail_settings USING (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text))) WITH CHECK (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text)));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_reminders USING (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text))) WITH CHECK (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text)));

CREATE POLICY lexigrid_tenant_isolation ON public.risk_treatments USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.risks USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.service_dependencies USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.users USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.vendor_assessments USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

CREATE POLICY lexigrid_tenant_isolation ON public.vendors USING (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text)) WITH CHECK (((tenant_id)::text = ((NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::character varying)::text));

ALTER TABLE public.loss_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.policies ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.remediations ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.requirements ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_assessments ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_comments ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_contacts ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_links ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_mail ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_mail_settings ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_reminders ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risk_treatments ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.risks ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.saml_replays ENABLE ROW LEVEL SECURITY;

CREATE POLICY saml_replays_tenant_policy ON public.saml_replays USING (((tenant_id)::text = current_setting('app.tenant_id'::text, true))) WITH CHECK (((tenant_id)::text = current_setting('app.tenant_id'::text, true)));

ALTER TABLE public.service_dependencies ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.vendor_assessments ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.vendors ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.workflow_decisions ENABLE ROW LEVEL SECURITY;

CREATE POLICY workflow_decisions_tenant_policy ON public.workflow_decisions USING (((tenant_id)::text = current_setting('app.tenant_id'::text, true))) WITH CHECK (((tenant_id)::text = current_setting('app.tenant_id'::text, true)));

ALTER TABLE public.workflow_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY workflow_delivery_tenant_policy ON public.workflow_deliveries USING (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text))) WITH CHECK (((tenant_id)::text = NULLIF(current_setting('app.tenant_id'::text, true), ''::text)));

ALTER TABLE public.workflow_notifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY workflow_notifications_tenant_policy ON public.workflow_notifications USING (((tenant_id)::text = current_setting('app.tenant_id'::text, true))) WITH CHECK (((tenant_id)::text = current_setting('app.tenant_id'::text, true)));

ALTER TABLE public.workflow_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY workflow_runs_tenant_policy ON public.workflow_runs USING (((tenant_id)::text = current_setting('app.tenant_id'::text, true))) WITH CHECK (((tenant_id)::text = current_setting('app.tenant_id'::text, true)));

GRANT USAGE ON SCHEMA public TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.approvals TO lexigrid_runtime;

GRANT SELECT,INSERT ON TABLE public.audit TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.business_services TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.control_findings TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.control_links TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.control_tests TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.controls TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.enterprise_records TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.enterprise_relations TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.evidence TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.evidence_blobs TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.frameworks TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.login_throttles TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.loss_events TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.mail_runtime_settings TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.policies TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.remediations TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.requirements TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.risk_assessments TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.risk_comments TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.risk_contacts TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.risk_links TO lexigrid_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE public.risk_mail TO lexigrid_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE public.risk_mail_settings TO lexigrid_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE public.risk_reminders TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.risk_treatments TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.risks TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.saml_replays TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.service_dependencies TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.tenants TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.users TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.vendor_assessments TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.vendors TO lexigrid_runtime;

GRANT SELECT,INSERT ON TABLE public.workflow_decisions TO lexigrid_runtime;

GRANT SELECT,INSERT,UPDATE ON TABLE public.workflow_deliveries TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.workflow_notifications TO lexigrid_runtime;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.workflow_runs TO lexigrid_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,DELETE,UPDATE ON TABLES TO lexigrid_runtime;
