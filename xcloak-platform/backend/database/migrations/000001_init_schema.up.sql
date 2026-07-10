--
-- PostgreSQL database dump
--


-- Dumped from database version 16.13
-- Dumped by pg_dump version 16.13

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
-- `true` (transaction-local), not pg_dump's default `false` (session-wide):
-- golang-migrate runs every migration file over one dedicated *sql.Conn, sent
-- as a single multi-statement message — which Postgres treats as one implicit
-- transaction. `false` would leave search_path empty on that connection for
-- every later migration file, and they don't all schema-qualify their DDL
-- like pg_dump output does, so they'd fail with "no schema has been selected
-- to create in". `true` reverts it once this migration's implicit
-- transaction ends, which is also when this file's own (schema-qualified)
-- statements are done needing it.
SELECT pg_catalog.set_config('search_path', '', true);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: agent_health; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_health (
    agent_id integer NOT NULL,
    health_score integer DEFAULT 100,
    health_status text DEFAULT 'healthy'::text,
    last_heartbeat timestamp with time zone,
    heartbeat_gap_s integer DEFAULT 0,
    task_success_rate double precision DEFAULT 1.0,
    alert_rate_1h integer DEFAULT 0,
    computed_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_heartbeats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_heartbeats (
    id integer NOT NULL,
    agent_id integer,
    "timestamp" timestamp without time zone DEFAULT now()
);


--
-- Name: agent_heartbeats_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_heartbeats_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_heartbeats_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_heartbeats_id_seq OWNED BY public.agent_heartbeats.id;


--
-- Name: agent_install_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_install_tokens (
    id integer NOT NULL,
    token text NOT NULL,
    label text DEFAULT ''::text,
    used boolean DEFAULT false,
    created_by text DEFAULT 'admin'::text NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval),
    created_at timestamp with time zone DEFAULT now(),
    used_at timestamp with time zone,
    used_by_agent_id integer
);


--
-- Name: agent_install_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_install_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_install_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_install_tokens_id_seq OWNED BY public.agent_install_tokens.id;


--
-- Name: agent_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_tasks (
    id integer NOT NULL,
    agent_id integer,
    task_type character varying(100),
    payload jsonb,
    status character varying(50) DEFAULT 'pending'::character varying,
    result text,
    created_at timestamp without time zone DEFAULT now(),
    completed_at timestamp without time zone,
    retry_count integer DEFAULT 0,
    last_error text DEFAULT ''::text,
    scheduled_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_tasks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_tasks_id_seq OWNED BY public.agent_tasks.id;


--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
    id integer NOT NULL,
    hostname character varying(255),
    os character varying(100),
    ip_address character varying(100),
    status character varying(50),
    last_seen timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    machine_id text DEFAULT ''::text NOT NULL,
    token text DEFAULT ''::text NOT NULL
);


--
-- Name: agents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agents_id_seq OWNED BY public.agents.id;


--
-- Name: ai_chat_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_chat_sessions (
    id integer NOT NULL,
    username text NOT NULL,
    messages jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: ai_chat_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ai_chat_sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ai_chat_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ai_chat_sessions_id_seq OWNED BY public.ai_chat_sessions.id;


--
-- Name: alert_metrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_metrics (
    id integer NOT NULL,
    bucket_time timestamp with time zone NOT NULL,
    severity text NOT NULL,
    count integer DEFAULT 0
);


--
-- Name: alert_metrics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alert_metrics_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_metrics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alert_metrics_id_seq OWNED BY public.alert_metrics.id;


--
-- Name: alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alerts (
    id integer NOT NULL,
    agent_id integer,
    severity character varying(20),
    rule_name character varying(255),
    log_message text,
    created_at timestamp without time zone DEFAULT now(),
    fingerprint character varying(255),
    mitre_tactic character varying(255),
    mitre_technique character varying(50),
    mitre_name character varying(255),
    suppressed_until timestamp with time zone,
    ai_summary text DEFAULT ''::text,
    ai_action text DEFAULT ''::text,
    ai_triaged_at timestamp with time zone,
    status text DEFAULT 'open'::text,
    acknowledged_by text,
    acknowledged_at timestamp with time zone,
    note text
);


--
-- Name: alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- Name: anomaly_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.anomaly_findings (
    id integer NOT NULL,
    agent_id integer NOT NULL,
    finding_type text NOT NULL,
    description text NOT NULL,
    severity text DEFAULT 'medium'::text,
    raw_context jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: anomaly_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.anomaly_findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: anomaly_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.anomaly_findings_id_seq OWNED BY public.anomaly_findings.id;


--
-- Name: asset_risk_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_risk_scores (
    id integer NOT NULL,
    agent_id integer,
    risk_score integer DEFAULT 0,
    risk_level character varying(50),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: asset_risk_scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.asset_risk_scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: asset_risk_scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.asset_risk_scores_id_seq OWNED BY public.asset_risk_scores.id;


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id integer NOT NULL,
    agent_id integer NOT NULL,
    event_id character varying(32) NOT NULL,
    ts character varying(32) NOT NULL,
    pid integer DEFAULT 0,
    ppid integer DEFAULT 0,
    uid integer DEFAULT 0,
    euid integer DEFAULT 0,
    username character varying(64) DEFAULT ''::character varying,
    comm character varying(64) DEFAULT ''::character varying,
    exe text DEFAULT ''::text,
    cmdline text DEFAULT ''::text,
    success character varying(4) DEFAULT ''::character varying,
    threat_tag character varying(64) DEFAULT ''::character varying,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: audit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_events_id_seq OWNED BY public.audit_events.id;


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id integer NOT NULL,
    action character varying(100),
    details text,
    created_at timestamp without time zone DEFAULT now(),
    username character varying(100),
    ip_address text DEFAULT ''::text
);


--
-- Name: audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_logs_id_seq OWNED BY public.audit_logs.id;


--
-- Name: brute_force_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.brute_force_state (
    agent_id integer NOT NULL,
    fail_count integer DEFAULT 0,
    window_start timestamp with time zone DEFAULT now(),
    last_alert timestamp with time zone
);


--
-- Name: collected_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collected_files (
    id integer NOT NULL,
    agent_id integer,
    original_path text,
    file_name text,
    stored_path text,
    collected_at timestamp without time zone DEFAULT now()
);


--
-- Name: collected_files_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.collected_files_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: collected_files_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.collected_files_id_seq OWNED BY public.collected_files.id;


--
-- Name: compliance_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_reports (
    id integer NOT NULL,
    title text NOT NULL,
    report_type text NOT NULL,
    generated_by text NOT NULL,
    summary jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: compliance_reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_reports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_reports_id_seq OWNED BY public.compliance_reports.id;


--
-- Name: compliance_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_scores (
    id integer NOT NULL,
    report_id integer NOT NULL,
    framework text NOT NULL,
    score integer NOT NULL,
    passed integer NOT NULL,
    failed integer NOT NULL,
    checks jsonb DEFAULT '[]'::jsonb,
    computed_at timestamp with time zone DEFAULT now()
);


--
-- Name: compliance_scores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_scores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_scores_id_seq OWNED BY public.compliance_scores.id;


--
-- Name: correlation_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.correlation_rules (
    id integer NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text,
    severity text DEFAULT ''::text,
    rule_name text DEFAULT ''::text,
    mitre_technique text DEFAULT ''::text,
    agent_id integer DEFAULT 0,
    action text NOT NULL,
    playbook_id integer DEFAULT 0,
    enabled boolean DEFAULT true,
    match_count integer DEFAULT 0,
    created_by text DEFAULT 'admin'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: correlation_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.correlation_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: correlation_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.correlation_rules_id_seq OWNED BY public.correlation_rules.id;


--
-- Name: cve_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cve_cache (
    cve_id text NOT NULL,
    cvss_score double precision DEFAULT 0,
    severity text DEFAULT 'unknown'::text,
    description text DEFAULT ''::text,
    published_at timestamp with time zone,
    fetched_at timestamp with time zone DEFAULT now()
);


--
-- Name: email_alert_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_alert_rules (
    id integer NOT NULL,
    name text NOT NULL,
    severity text DEFAULT 'critical'::text NOT NULL,
    recipient text NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: email_alert_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.email_alert_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: email_alert_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.email_alert_rules_id_seq OWNED BY public.email_alert_rules.id;


--
-- Name: endpoint_connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_connections (
    id integer NOT NULL,
    agent_id integer,
    protocol character varying(20),
    local_address text,
    remote_address text,
    state character varying(50),
    collected_at timestamp without time zone DEFAULT now(),
    country text DEFAULT ''::text,
    country_code text DEFAULT ''::text,
    is_proxy boolean DEFAULT false
);


--
-- Name: endpoint_connections_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endpoint_connections_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endpoint_connections_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endpoint_connections_id_seq OWNED BY public.endpoint_connections.id;


--
-- Name: endpoint_file_hashes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_file_hashes (
    id integer NOT NULL,
    agent_id integer,
    file_path text,
    md5_hash text,
    sha256_hash text,
    collected_at timestamp without time zone DEFAULT now(),
    file_name text DEFAULT ''::text NOT NULL,
    file_size bigint DEFAULT 0 NOT NULL
);


--
-- Name: endpoint_file_hashes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endpoint_file_hashes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endpoint_file_hashes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endpoint_file_hashes_id_seq OWNED BY public.endpoint_file_hashes.id;


--
-- Name: endpoint_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_logs (
    id integer NOT NULL,
    agent_id integer,
    log_source character varying(100),
    log_message text,
    collected_at timestamp without time zone DEFAULT now(),
    parsed_fields jsonb DEFAULT '{}'::jsonb
);


--
-- Name: endpoint_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endpoint_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endpoint_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endpoint_logs_id_seq OWNED BY public.endpoint_logs.id;


--
-- Name: endpoint_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_packages (
    id integer NOT NULL,
    agent_id integer,
    package_name character varying(255),
    version character varying(255),
    collected_at timestamp without time zone DEFAULT now()
);


--
-- Name: endpoint_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endpoint_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endpoint_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endpoint_packages_id_seq OWNED BY public.endpoint_packages.id;


--
-- Name: endpoint_processes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_processes (
    id integer NOT NULL,
    agent_id integer,
    pid integer,
    process_name character varying(255),
    collected_at timestamp without time zone DEFAULT now(),
    ppid integer DEFAULT 0,
    cmdline text DEFAULT ''::text,
    username character varying(64) DEFAULT ''::character varying,
    cpu_percent character varying(10) DEFAULT ''::character varying,
    mem_percent character varying(10) DEFAULT ''::character varying,
    exe_path text DEFAULT ''::text
);


--
-- Name: endpoint_processes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endpoint_processes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endpoint_processes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endpoint_processes_id_seq OWNED BY public.endpoint_processes.id;


--
-- Name: endpoint_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_services (
    id integer NOT NULL,
    agent_id integer,
    service_name character varying(255),
    service_state character varying(50),
    collected_at timestamp without time zone DEFAULT now()
);


--
-- Name: endpoint_services_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endpoint_services_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endpoint_services_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endpoint_services_id_seq OWNED BY public.endpoint_services.id;


--
-- Name: endpoint_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.endpoint_users (
    id integer NOT NULL,
    agent_id integer,
    username character varying(255),
    uid integer,
    shell character varying(255),
    collected_at timestamp without time zone DEFAULT now()
);


--
-- Name: endpoint_users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.endpoint_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: endpoint_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.endpoint_users_id_seq OWNED BY public.endpoint_users.id;


--
-- Name: fim_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fim_alerts (
    id integer NOT NULL,
    agent_id integer NOT NULL,
    file_path text NOT NULL,
    change_type text NOT NULL,
    old_hash text DEFAULT ''::text,
    new_hash text DEFAULT ''::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: fim_alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fim_alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fim_alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fim_alerts_id_seq OWNED BY public.fim_alerts.id;


--
-- Name: fim_baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fim_baselines (
    id integer NOT NULL,
    agent_id integer NOT NULL,
    file_path text NOT NULL,
    sha256_hash text NOT NULL,
    file_size bigint DEFAULT 0,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: fim_baselines_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fim_baselines_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fim_baselines_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fim_baselines_id_seq OWNED BY public.fim_baselines.id;


--
-- Name: firewall_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.firewall_rules (
    id integer NOT NULL,
    name character varying(100),
    source_ip character varying(100),
    destination_ip character varying(50),
    protocol character varying(20),
    port integer,
    action character varying(20),
    enabled boolean DEFAULT true,
    synced_at timestamp with time zone,
    priority integer DEFAULT 100 NOT NULL
);


--
-- Name: firewall_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.firewall_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: firewall_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.firewall_rules_id_seq OWNED BY public.firewall_rules.id;


--
-- Name: firewall_sync_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.firewall_sync_log (
    id integer NOT NULL,
    agent_id integer NOT NULL,
    task_id integer DEFAULT 0 NOT NULL,
    rule_count integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'dispatched'::text NOT NULL,
    result text DEFAULT ''::text,
    synced_by text DEFAULT 'admin'::text NOT NULL,
    synced_at timestamp with time zone DEFAULT now()
);


--
-- Name: firewall_sync_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.firewall_sync_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: firewall_sync_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.firewall_sync_log_id_seq OWNED BY public.firewall_sync_log.id;


--
-- Name: geoip_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.geoip_cache (
    ip text NOT NULL,
    country text DEFAULT ''::text,
    country_code text DEFAULT ''::text,
    city text DEFAULT ''::text,
    isp text DEFAULT ''::text,
    is_proxy boolean DEFAULT false,
    fetched_at timestamp with time zone DEFAULT now()
);


--
-- Name: hunt_queries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.hunt_queries (
    id integer NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text,
    query_type text NOT NULL,
    query_text text NOT NULL,
    created_by text NOT NULL,
    hit_count integer DEFAULT 0,
    last_run_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: hunt_queries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.hunt_queries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: hunt_queries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.hunt_queries_id_seq OWNED BY public.hunt_queries.id;


--
-- Name: hunt_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.hunt_results (
    id integer NOT NULL,
    query_id integer NOT NULL,
    agent_id integer NOT NULL,
    result jsonb NOT NULL,
    found_at timestamp with time zone DEFAULT now()
);


--
-- Name: hunt_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.hunt_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: hunt_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.hunt_results_id_seq OWNED BY public.hunt_results.id;


--
-- Name: incident_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incident_events (
    id integer NOT NULL,
    incident_id integer,
    event_type character varying(255),
    details text,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: incident_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incident_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incident_events_id_seq OWNED BY public.incident_events.id;


--
-- Name: incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incidents (
    id integer NOT NULL,
    agent_id integer,
    title character varying(255),
    severity character varying(50),
    status character varying(50) DEFAULT 'open'::character varying,
    description text,
    created_at timestamp without time zone DEFAULT now(),
    fingerprint character varying(255),
    ai_summary text DEFAULT ''::text,
    ai_triaged_at timestamp with time zone,
    resolved_at timestamp with time zone,
    mttr_seconds bigint
);


--
-- Name: incidents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incidents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incidents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incidents_id_seq OWNED BY public.incidents.id;


--
-- Name: integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integrations (
    id integer NOT NULL,
    name text NOT NULL,
    enabled boolean DEFAULT false,
    config jsonb DEFAULT '{}'::jsonb,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by text DEFAULT 'admin'::text
);


--
-- Name: integrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.integrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: integrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.integrations_id_seq OWNED BY public.integrations.id;


--
-- Name: ioc_firewall_blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_firewall_blocks (
    id integer NOT NULL,
    ioc_id integer NOT NULL,
    indicator text NOT NULL,
    agent_id integer NOT NULL,
    rule_id integer,
    blocked_at timestamp with time zone DEFAULT now()
);


--
-- Name: ioc_firewall_blocks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_firewall_blocks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_firewall_blocks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_firewall_blocks_id_seq OWNED BY public.ioc_firewall_blocks.id;


--
-- Name: iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.iocs (
    id integer NOT NULL,
    indicator text NOT NULL,
    type character varying(50) NOT NULL,
    severity character varying(50),
    description text,
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: iocs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.iocs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: iocs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.iocs_id_seq OWNED BY public.iocs.id;


--
-- Name: mitre_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_mappings (
    id integer NOT NULL,
    rule_name text NOT NULL,
    tactic text NOT NULL,
    technique text NOT NULL,
    name text NOT NULL
);


--
-- Name: mitre_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mitre_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mitre_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mitre_mappings_id_seq OWNED BY public.mitre_mappings.id;


--
-- Name: playbook_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_actions (
    id integer NOT NULL,
    playbook_id integer,
    step_order integer,
    action_type character varying(100),
    payload jsonb,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: playbook_actions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.playbook_actions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: playbook_actions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.playbook_actions_id_seq OWNED BY public.playbook_actions.id;


--
-- Name: playbook_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_executions (
    id integer NOT NULL,
    playbook_id integer,
    agent_id integer,
    alert_rule character varying(255),
    action_type character varying(255),
    status character varying(50),
    created_at timestamp without time zone DEFAULT now(),
    error_detail text DEFAULT ''::text,
    task_id integer DEFAULT 0
);


--
-- Name: playbook_executions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.playbook_executions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: playbook_executions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.playbook_executions_id_seq OWNED BY public.playbook_executions.id;


--
-- Name: playbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbooks (
    id integer NOT NULL,
    name character varying(255),
    trigger_type character varying(100),
    action_type character varying(100),
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: playbooks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.playbooks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: playbooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.playbooks_id_seq OWNED BY public.playbooks.id;


--
-- Name: quarantined_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.quarantined_files (
    id integer NOT NULL,
    agent_id integer,
    original_path text NOT NULL,
    quarantine_path text NOT NULL,
    file_name character varying(255),
    reason text,
    quarantined_at timestamp without time zone DEFAULT now()
);


--
-- Name: quarantined_files_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.quarantined_files_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: quarantined_files_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.quarantined_files_id_seq OWNED BY public.quarantined_files.id;


--
-- Name: rate_limit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rate_limit_events (
    id integer NOT NULL,
    ip text NOT NULL,
    path text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: rate_limit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.rate_limit_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rate_limit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rate_limit_events_id_seq OWNED BY public.rate_limit_events.id;


--
-- Name: registry_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.registry_entries (
    id integer NOT NULL,
    agent_id integer NOT NULL,
    hive character varying(16) DEFAULT ''::character varying NOT NULL,
    key_path text DEFAULT ''::text NOT NULL,
    name character varying(256) DEFAULT ''::character varying NOT NULL,
    type character varying(32) DEFAULT ''::character varying,
    data text DEFAULT ''::text,
    threat_tag character varying(64) DEFAULT ''::character varying,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: registry_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.registry_entries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: registry_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.registry_entries_id_seq OWNED BY public.registry_entries.id;


--
-- Name: scheduled_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduled_tasks (
    id integer NOT NULL,
    name text NOT NULL,
    task_type text NOT NULL,
    agent_ids integer[] DEFAULT '{}'::integer[],
    cron_expr text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    last_run_at timestamp with time zone,
    next_run_at timestamp with time zone,
    run_count integer DEFAULT 0,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: scheduled_tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scheduled_tasks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scheduled_tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scheduled_tasks_id_seq OWNED BY public.scheduled_tasks.id;


--
-- Name: sigma_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sigma_rules (
    id integer NOT NULL,
    title character varying(255) NOT NULL,
    severity character varying(50),
    mitre_tactic character varying(255),
    mitre_technique character varying(50),
    mitre_name character varying(255),
    keywords jsonb,
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT now(),
    selections jsonb DEFAULT '{}'::jsonb,
    condition text DEFAULT ''::text
);


--
-- Name: sigma_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sigma_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sigma_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sigma_rules_id_seq OWNED BY public.sigma_rules.id;


--
-- Name: suppression_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.suppression_rules (
    id integer NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text,
    rule_name text DEFAULT ''::text,
    agent_id integer DEFAULT 0,
    severity text DEFAULT ''::text,
    mitre_technique text DEFAULT ''::text,
    window_minutes integer DEFAULT 60,
    expires_at timestamp with time zone,
    enabled boolean DEFAULT true,
    match_count integer DEFAULT 0,
    created_by text DEFAULT 'admin'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    dedup_window_minutes integer DEFAULT 10
);


--
-- Name: suppression_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.suppression_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: suppression_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.suppression_rules_id_seq OWNED BY public.suppression_rules.id;


--
-- Name: suppression_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.suppression_state (
    suppression_id integer NOT NULL,
    agent_id integer NOT NULL,
    rule_name text NOT NULL,
    last_matched timestamp with time zone DEFAULT now()
);


--
-- Name: threat_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_feeds (
    id integer NOT NULL,
    name character varying(255),
    source character varying(500),
    enabled boolean DEFAULT true,
    last_sync timestamp without time zone,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: threat_feeds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.threat_feeds_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_feeds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.threat_feeds_id_seq OWNED BY public.threat_feeds.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash text NOT NULL,
    role character varying(50) DEFAULT 'admin'::character varying,
    created_at timestamp without time zone DEFAULT now(),
    last_login timestamp with time zone,
    is_active boolean DEFAULT true,
    totp_secret text,
    totp_enabled boolean DEFAULT false,
    totp_verified boolean DEFAULT false,
    password_reset_token text,
    password_reset_expiry timestamp with time zone
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerabilities (
    id integer NOT NULL,
    agent_id integer,
    package_name character varying(255),
    package_version character varying(255),
    cve_id character varying(100),
    severity character varying(50),
    cvss_score numeric(4,1),
    description text,
    detected_at timestamp without time zone DEFAULT now(),
    name text DEFAULT ''::text,
    remediation text DEFAULT ''::text
);


--
-- Name: vulnerabilities_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerabilities_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerabilities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerabilities_id_seq OWNED BY public.vulnerabilities.id;


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id integer NOT NULL,
    integration text NOT NULL,
    event_type text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb,
    status_code integer,
    success boolean DEFAULT false,
    error_msg text DEFAULT ''::text,
    delivered_at timestamp with time zone DEFAULT now()
);


--
-- Name: webhook_deliveries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.webhook_deliveries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: webhook_deliveries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.webhook_deliveries_id_seq OWNED BY public.webhook_deliveries.id;


--
-- Name: yara_matches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.yara_matches (
    id integer NOT NULL,
    agent_id integer,
    file_path text,
    rule_name character varying(255),
    severity character varying(50),
    description text,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: yara_matches_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.yara_matches_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: yara_matches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.yara_matches_id_seq OWNED BY public.yara_matches.id;


--
-- Name: yara_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.yara_rules (
    id integer NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text,
    rule_content text NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: yara_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.yara_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: yara_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.yara_rules_id_seq OWNED BY public.yara_rules.id;


--
-- Name: agent_heartbeats id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_heartbeats ALTER COLUMN id SET DEFAULT nextval('public.agent_heartbeats_id_seq'::regclass);


--
-- Name: agent_install_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_install_tokens ALTER COLUMN id SET DEFAULT nextval('public.agent_install_tokens_id_seq'::regclass);


--
-- Name: agent_tasks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_tasks ALTER COLUMN id SET DEFAULT nextval('public.agent_tasks_id_seq'::regclass);


--
-- Name: agents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents ALTER COLUMN id SET DEFAULT nextval('public.agents_id_seq'::regclass);


--
-- Name: ai_chat_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_chat_sessions ALTER COLUMN id SET DEFAULT nextval('public.ai_chat_sessions_id_seq'::regclass);


--
-- Name: alert_metrics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_metrics ALTER COLUMN id SET DEFAULT nextval('public.alert_metrics_id_seq'::regclass);


--
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- Name: anomaly_findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.anomaly_findings ALTER COLUMN id SET DEFAULT nextval('public.anomaly_findings_id_seq'::regclass);


--
-- Name: asset_risk_scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_risk_scores ALTER COLUMN id SET DEFAULT nextval('public.asset_risk_scores_id_seq'::regclass);


--
-- Name: audit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events ALTER COLUMN id SET DEFAULT nextval('public.audit_events_id_seq'::regclass);


--
-- Name: audit_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs ALTER COLUMN id SET DEFAULT nextval('public.audit_logs_id_seq'::regclass);


--
-- Name: collected_files id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collected_files ALTER COLUMN id SET DEFAULT nextval('public.collected_files_id_seq'::regclass);


--
-- Name: compliance_reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_reports ALTER COLUMN id SET DEFAULT nextval('public.compliance_reports_id_seq'::regclass);


--
-- Name: compliance_scores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_scores ALTER COLUMN id SET DEFAULT nextval('public.compliance_scores_id_seq'::regclass);


--
-- Name: correlation_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_rules ALTER COLUMN id SET DEFAULT nextval('public.correlation_rules_id_seq'::regclass);


--
-- Name: email_alert_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_alert_rules ALTER COLUMN id SET DEFAULT nextval('public.email_alert_rules_id_seq'::regclass);


--
-- Name: endpoint_connections id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_connections ALTER COLUMN id SET DEFAULT nextval('public.endpoint_connections_id_seq'::regclass);


--
-- Name: endpoint_file_hashes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_file_hashes ALTER COLUMN id SET DEFAULT nextval('public.endpoint_file_hashes_id_seq'::regclass);


--
-- Name: endpoint_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_logs ALTER COLUMN id SET DEFAULT nextval('public.endpoint_logs_id_seq'::regclass);


--
-- Name: endpoint_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_packages ALTER COLUMN id SET DEFAULT nextval('public.endpoint_packages_id_seq'::regclass);


--
-- Name: endpoint_processes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_processes ALTER COLUMN id SET DEFAULT nextval('public.endpoint_processes_id_seq'::regclass);


--
-- Name: endpoint_services id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_services ALTER COLUMN id SET DEFAULT nextval('public.endpoint_services_id_seq'::regclass);


--
-- Name: endpoint_users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_users ALTER COLUMN id SET DEFAULT nextval('public.endpoint_users_id_seq'::regclass);


--
-- Name: fim_alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fim_alerts ALTER COLUMN id SET DEFAULT nextval('public.fim_alerts_id_seq'::regclass);


--
-- Name: fim_baselines id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fim_baselines ALTER COLUMN id SET DEFAULT nextval('public.fim_baselines_id_seq'::regclass);


--
-- Name: firewall_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firewall_rules ALTER COLUMN id SET DEFAULT nextval('public.firewall_rules_id_seq'::regclass);


--
-- Name: firewall_sync_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firewall_sync_log ALTER COLUMN id SET DEFAULT nextval('public.firewall_sync_log_id_seq'::regclass);


--
-- Name: hunt_queries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hunt_queries ALTER COLUMN id SET DEFAULT nextval('public.hunt_queries_id_seq'::regclass);


--
-- Name: hunt_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hunt_results ALTER COLUMN id SET DEFAULT nextval('public.hunt_results_id_seq'::regclass);


--
-- Name: incident_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_events ALTER COLUMN id SET DEFAULT nextval('public.incident_events_id_seq'::regclass);


--
-- Name: incidents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents ALTER COLUMN id SET DEFAULT nextval('public.incidents_id_seq'::regclass);


--
-- Name: integrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integrations ALTER COLUMN id SET DEFAULT nextval('public.integrations_id_seq'::regclass);


--
-- Name: ioc_firewall_blocks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_firewall_blocks ALTER COLUMN id SET DEFAULT nextval('public.ioc_firewall_blocks_id_seq'::regclass);


--
-- Name: iocs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iocs ALTER COLUMN id SET DEFAULT nextval('public.iocs_id_seq'::regclass);


--
-- Name: mitre_mappings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_mappings ALTER COLUMN id SET DEFAULT nextval('public.mitre_mappings_id_seq'::regclass);


--
-- Name: playbook_actions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_actions ALTER COLUMN id SET DEFAULT nextval('public.playbook_actions_id_seq'::regclass);


--
-- Name: playbook_executions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_executions ALTER COLUMN id SET DEFAULT nextval('public.playbook_executions_id_seq'::regclass);


--
-- Name: playbooks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbooks ALTER COLUMN id SET DEFAULT nextval('public.playbooks_id_seq'::regclass);


--
-- Name: quarantined_files id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_files ALTER COLUMN id SET DEFAULT nextval('public.quarantined_files_id_seq'::regclass);


--
-- Name: rate_limit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limit_events ALTER COLUMN id SET DEFAULT nextval('public.rate_limit_events_id_seq'::regclass);


--
-- Name: registry_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registry_entries ALTER COLUMN id SET DEFAULT nextval('public.registry_entries_id_seq'::regclass);


--
-- Name: scheduled_tasks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_tasks ALTER COLUMN id SET DEFAULT nextval('public.scheduled_tasks_id_seq'::regclass);


--
-- Name: sigma_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sigma_rules ALTER COLUMN id SET DEFAULT nextval('public.sigma_rules_id_seq'::regclass);


--
-- Name: suppression_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppression_rules ALTER COLUMN id SET DEFAULT nextval('public.suppression_rules_id_seq'::regclass);


--
-- Name: threat_feeds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feeds ALTER COLUMN id SET DEFAULT nextval('public.threat_feeds_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: vulnerabilities id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities ALTER COLUMN id SET DEFAULT nextval('public.vulnerabilities_id_seq'::regclass);


--
-- Name: webhook_deliveries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries ALTER COLUMN id SET DEFAULT nextval('public.webhook_deliveries_id_seq'::regclass);


--
-- Name: yara_matches id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_matches ALTER COLUMN id SET DEFAULT nextval('public.yara_matches_id_seq'::regclass);


--
-- Name: yara_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_rules ALTER COLUMN id SET DEFAULT nextval('public.yara_rules_id_seq'::regclass);


--
-- Name: agent_health agent_health_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_health
    ADD CONSTRAINT agent_health_pkey PRIMARY KEY (agent_id);


--
-- Name: agent_heartbeats agent_heartbeats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_heartbeats
    ADD CONSTRAINT agent_heartbeats_pkey PRIMARY KEY (id);


--
-- Name: agent_install_tokens agent_install_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_install_tokens
    ADD CONSTRAINT agent_install_tokens_pkey PRIMARY KEY (id);


--
-- Name: agent_install_tokens agent_install_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_install_tokens
    ADD CONSTRAINT agent_install_tokens_token_key UNIQUE (token);


--
-- Name: agent_tasks agent_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_tasks
    ADD CONSTRAINT agent_tasks_pkey PRIMARY KEY (id);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);


--
-- Name: ai_chat_sessions ai_chat_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_chat_sessions
    ADD CONSTRAINT ai_chat_sessions_pkey PRIMARY KEY (id);


--
-- Name: alert_metrics alert_metrics_bucket_time_severity_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_metrics
    ADD CONSTRAINT alert_metrics_bucket_time_severity_key UNIQUE (bucket_time, severity);


--
-- Name: alert_metrics alert_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_metrics
    ADD CONSTRAINT alert_metrics_pkey PRIMARY KEY (id);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- Name: anomaly_findings anomaly_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.anomaly_findings
    ADD CONSTRAINT anomaly_findings_pkey PRIMARY KEY (id);


--
-- Name: asset_risk_scores asset_risk_scores_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_risk_scores
    ADD CONSTRAINT asset_risk_scores_agent_id_key UNIQUE (agent_id);


--
-- Name: asset_risk_scores asset_risk_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_risk_scores
    ADD CONSTRAINT asset_risk_scores_pkey PRIMARY KEY (id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: brute_force_state brute_force_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.brute_force_state
    ADD CONSTRAINT brute_force_state_pkey PRIMARY KEY (agent_id);


--
-- Name: collected_files collected_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collected_files
    ADD CONSTRAINT collected_files_pkey PRIMARY KEY (id);


--
-- Name: compliance_reports compliance_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_reports
    ADD CONSTRAINT compliance_reports_pkey PRIMARY KEY (id);


--
-- Name: compliance_scores compliance_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_scores
    ADD CONSTRAINT compliance_scores_pkey PRIMARY KEY (id);


--
-- Name: correlation_rules correlation_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_rules
    ADD CONSTRAINT correlation_rules_pkey PRIMARY KEY (id);


--
-- Name: cve_cache cve_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_cache
    ADD CONSTRAINT cve_cache_pkey PRIMARY KEY (cve_id);


--
-- Name: email_alert_rules email_alert_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_alert_rules
    ADD CONSTRAINT email_alert_rules_pkey PRIMARY KEY (id);


--
-- Name: endpoint_connections endpoint_connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_connections
    ADD CONSTRAINT endpoint_connections_pkey PRIMARY KEY (id);


--
-- Name: endpoint_file_hashes endpoint_file_hashes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_file_hashes
    ADD CONSTRAINT endpoint_file_hashes_pkey PRIMARY KEY (id);


--
-- Name: endpoint_logs endpoint_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_logs
    ADD CONSTRAINT endpoint_logs_pkey PRIMARY KEY (id);


--
-- Name: endpoint_packages endpoint_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_packages
    ADD CONSTRAINT endpoint_packages_pkey PRIMARY KEY (id);


--
-- Name: endpoint_processes endpoint_processes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_processes
    ADD CONSTRAINT endpoint_processes_pkey PRIMARY KEY (id);


--
-- Name: endpoint_services endpoint_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_services
    ADD CONSTRAINT endpoint_services_pkey PRIMARY KEY (id);


--
-- Name: endpoint_users endpoint_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_users
    ADD CONSTRAINT endpoint_users_pkey PRIMARY KEY (id);


--
-- Name: fim_alerts fim_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fim_alerts
    ADD CONSTRAINT fim_alerts_pkey PRIMARY KEY (id);


--
-- Name: fim_baselines fim_baselines_agent_id_file_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fim_baselines
    ADD CONSTRAINT fim_baselines_agent_id_file_path_key UNIQUE (agent_id, file_path);


--
-- Name: fim_baselines fim_baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fim_baselines
    ADD CONSTRAINT fim_baselines_pkey PRIMARY KEY (id);


--
-- Name: firewall_rules firewall_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firewall_rules
    ADD CONSTRAINT firewall_rules_pkey PRIMARY KEY (id);


--
-- Name: firewall_sync_log firewall_sync_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firewall_sync_log
    ADD CONSTRAINT firewall_sync_log_pkey PRIMARY KEY (id);


--
-- Name: geoip_cache geoip_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.geoip_cache
    ADD CONSTRAINT geoip_cache_pkey PRIMARY KEY (ip);


--
-- Name: hunt_queries hunt_queries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hunt_queries
    ADD CONSTRAINT hunt_queries_pkey PRIMARY KEY (id);


--
-- Name: hunt_results hunt_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hunt_results
    ADD CONSTRAINT hunt_results_pkey PRIMARY KEY (id);


--
-- Name: incident_events incident_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_events
    ADD CONSTRAINT incident_events_pkey PRIMARY KEY (id);


--
-- Name: incidents incidents_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_fingerprint_key UNIQUE (fingerprint);


--
-- Name: incidents incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_pkey PRIMARY KEY (id);


--
-- Name: integrations integrations_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_name_key UNIQUE (name);


--
-- Name: integrations integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_pkey PRIMARY KEY (id);


--
-- Name: ioc_firewall_blocks ioc_firewall_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_firewall_blocks
    ADD CONSTRAINT ioc_firewall_blocks_pkey PRIMARY KEY (id);


--
-- Name: iocs iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iocs
    ADD CONSTRAINT iocs_pkey PRIMARY KEY (id);


--
-- Name: mitre_mappings mitre_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_mappings
    ADD CONSTRAINT mitre_mappings_pkey PRIMARY KEY (id);


--
-- Name: mitre_mappings mitre_mappings_rule_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_mappings
    ADD CONSTRAINT mitre_mappings_rule_name_key UNIQUE (rule_name);


--
-- Name: playbook_actions playbook_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_actions
    ADD CONSTRAINT playbook_actions_pkey PRIMARY KEY (id);


--
-- Name: playbook_executions playbook_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_pkey PRIMARY KEY (id);


--
-- Name: playbooks playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbooks
    ADD CONSTRAINT playbooks_pkey PRIMARY KEY (id);


--
-- Name: quarantined_files quarantined_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_files
    ADD CONSTRAINT quarantined_files_pkey PRIMARY KEY (id);


--
-- Name: rate_limit_events rate_limit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limit_events
    ADD CONSTRAINT rate_limit_events_pkey PRIMARY KEY (id);


--
-- Name: registry_entries registry_entries_agent_id_hive_key_path_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registry_entries
    ADD CONSTRAINT registry_entries_agent_id_hive_key_path_name_key UNIQUE (agent_id, hive, key_path, name);


--
-- Name: registry_entries registry_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registry_entries
    ADD CONSTRAINT registry_entries_pkey PRIMARY KEY (id);


--
-- Name: scheduled_tasks scheduled_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_pkey PRIMARY KEY (id);


--
-- Name: sigma_rules sigma_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sigma_rules
    ADD CONSTRAINT sigma_rules_pkey PRIMARY KEY (id);


--
-- Name: suppression_rules suppression_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppression_rules
    ADD CONSTRAINT suppression_rules_pkey PRIMARY KEY (id);


--
-- Name: suppression_state suppression_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppression_state
    ADD CONSTRAINT suppression_state_pkey PRIMARY KEY (suppression_id, agent_id, rule_name);


--
-- Name: threat_feeds threat_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feeds
    ADD CONSTRAINT threat_feeds_pkey PRIMARY KEY (id);


--
-- Name: iocs unique_ioc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iocs
    ADD CONSTRAINT unique_ioc UNIQUE (indicator, type);


--
-- Name: endpoint_file_hashes uq_agent_file_path; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_file_hashes
    ADD CONSTRAINT uq_agent_file_path UNIQUE (agent_id, file_path);


--
-- Name: agents uq_agent_machine_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT uq_agent_machine_id UNIQUE (machine_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: yara_matches yara_matches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_matches
    ADD CONSTRAINT yara_matches_pkey PRIMARY KEY (id);


--
-- Name: yara_rules yara_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_rules
    ADD CONSTRAINT yara_rules_pkey PRIMARY KEY (id);


--
-- Name: idx_ae_agent_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ae_agent_time ON public.audit_events USING btree (agent_id, created_at DESC);


--
-- Name: idx_ae_cmdline_fts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ae_cmdline_fts ON public.audit_events USING gin (to_tsvector('simple'::regconfig, cmdline));


--
-- Name: idx_ae_exe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ae_exe ON public.audit_events USING btree (exe);


--
-- Name: idx_ae_threat_tag; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ae_threat_tag ON public.audit_events USING btree (threat_tag) WHERE ((threat_tag)::text <> ''::text);


--
-- Name: idx_agent_machine_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_machine_id ON public.agents USING btree (machine_id);


--
-- Name: idx_agent_tasks_agent_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_tasks_agent_status ON public.agent_tasks USING btree (agent_id, status, created_at DESC);


--
-- Name: idx_agent_tasks_pending_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_tasks_pending_created ON public.agent_tasks USING btree (status, created_at) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_agent_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_agent_token ON public.agents USING btree (token);


--
-- Name: idx_ai_sessions_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_sessions_user ON public.ai_chat_sessions USING btree (username, updated_at DESC);


--
-- Name: idx_alert_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_fingerprint ON public.alerts USING btree (fingerprint);


--
-- Name: idx_alert_metrics_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_metrics_time ON public.alert_metrics USING btree (bucket_time DESC);


--
-- Name: idx_alerts_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_agent_id ON public.alerts USING btree (agent_id);


--
-- Name: idx_alerts_agent_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_agent_severity ON public.alerts USING btree (agent_id, severity, created_at DESC);


--
-- Name: idx_alerts_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_created_at ON public.alerts USING btree (created_at DESC);


--
-- Name: idx_alerts_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_fingerprint ON public.alerts USING btree (fingerprint);


--
-- Name: idx_alerts_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_severity ON public.alerts USING btree (severity);


--
-- Name: idx_alerts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_status ON public.alerts USING btree (status, created_at DESC);


--
-- Name: idx_anomaly_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anomaly_agent ON public.anomaly_findings USING btree (agent_id, created_at DESC);


--
-- Name: idx_audit_logs_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_created_at ON public.audit_logs USING btree (created_at DESC);


--
-- Name: idx_compliance_reports_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_compliance_reports_type ON public.compliance_reports USING btree (report_type, created_at DESC);


--
-- Name: idx_compliance_scores_report; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_compliance_scores_report ON public.compliance_scores USING btree (report_id);


--
-- Name: idx_cve_cache_fetched; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cve_cache_fetched ON public.cve_cache USING btree (fetched_at DESC);


--
-- Name: idx_el_auth_result; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_el_auth_result ON public.endpoint_logs USING btree (((parsed_fields ->> 'auth_result'::text))) WHERE ((parsed_fields ->> 'auth_result'::text) IS NOT NULL);


--
-- Name: idx_el_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_el_event_id ON public.endpoint_logs USING btree (((parsed_fields ->> 'event_id'::text))) WHERE ((parsed_fields ->> 'event_id'::text) IS NOT NULL);


--
-- Name: idx_el_parsed_fields_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_el_parsed_fields_gin ON public.endpoint_logs USING gin (parsed_fields);


--
-- Name: idx_el_src_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_el_src_ip ON public.endpoint_logs USING btree (((parsed_fields ->> 'src_ip'::text))) WHERE ((parsed_fields ->> 'src_ip'::text) IS NOT NULL);


--
-- Name: idx_el_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_el_user ON public.endpoint_logs USING btree (((parsed_fields ->> 'user'::text))) WHERE ((parsed_fields ->> 'user'::text) IS NOT NULL);


--
-- Name: idx_endpoint_connections_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endpoint_connections_agent ON public.endpoint_connections USING btree (agent_id);


--
-- Name: idx_endpoint_logs_agent_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endpoint_logs_agent_source ON public.endpoint_logs USING btree (agent_id, log_source);


--
-- Name: idx_endpoint_logs_agent_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endpoint_logs_agent_time ON public.endpoint_logs USING btree (agent_id, id DESC);


--
-- Name: idx_endpoint_packages_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endpoint_packages_agent ON public.endpoint_packages USING btree (agent_id);


--
-- Name: idx_endpoint_processes_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_endpoint_processes_agent ON public.endpoint_processes USING btree (agent_id);


--
-- Name: idx_ep_cmdline_fts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ep_cmdline_fts ON public.endpoint_processes USING gin (to_tsvector('simple'::regconfig, cmdline));


--
-- Name: idx_filehash_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_filehash_agent ON public.endpoint_file_hashes USING btree (agent_id);


--
-- Name: idx_filehash_md5; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_filehash_md5 ON public.endpoint_file_hashes USING btree (md5_hash);


--
-- Name: idx_filehash_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_filehash_sha256 ON public.endpoint_file_hashes USING btree (sha256_hash);


--
-- Name: idx_fim_alerts_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fim_alerts_agent ON public.fim_alerts USING btree (agent_id, created_at DESC);


--
-- Name: idx_fim_baselines_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fim_baselines_agent ON public.fim_baselines USING btree (agent_id);


--
-- Name: idx_firewall_sync_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_firewall_sync_agent ON public.firewall_sync_log USING btree (agent_id, synced_at DESC);


--
-- Name: idx_hunt_results_query; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_hunt_results_query ON public.hunt_results USING btree (query_id, found_at DESC);


--
-- Name: idx_incidents_agent_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_agent_status ON public.incidents USING btree (agent_id, status);


--
-- Name: idx_incidents_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_created_at ON public.incidents USING btree (created_at DESC);


--
-- Name: idx_incidents_severity_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_severity_created ON public.incidents USING btree (severity, created_at DESC);


--
-- Name: idx_incidents_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_status ON public.incidents USING btree (status);


--
-- Name: idx_incidents_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_incidents_status_created ON public.incidents USING btree (status, created_at DESC);


--
-- Name: idx_install_tokens_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_install_tokens_token ON public.agent_install_tokens USING btree (token);


--
-- Name: idx_rate_limit_ip_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rate_limit_ip_time ON public.rate_limit_events USING btree (ip, created_at DESC);


--
-- Name: idx_re_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_re_agent ON public.registry_entries USING btree (agent_id);


--
-- Name: idx_re_threat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_re_threat ON public.registry_entries USING btree (threat_tag) WHERE ((threat_tag)::text <> ''::text);


--
-- Name: idx_suppression_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_suppression_enabled ON public.suppression_rules USING btree (enabled);


--
-- Name: idx_users_reset_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_reset_token ON public.users USING btree (password_reset_token) WHERE (password_reset_token IS NOT NULL);


--
-- Name: idx_vuln_agent_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vuln_agent_severity ON public.vulnerabilities USING btree (agent_id, severity);


--
-- Name: idx_vulnerabilities_agent_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_agent_severity ON public.vulnerabilities USING btree (agent_id, severity);


--
-- Name: idx_webhook_deliveries_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_deliveries_time ON public.webhook_deliveries USING btree (delivered_at DESC);


--
-- Name: agent_heartbeats agent_heartbeats_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_heartbeats
    ADD CONSTRAINT agent_heartbeats_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: agent_tasks agent_tasks_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_tasks
    ADD CONSTRAINT agent_tasks_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: alerts alerts_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: asset_risk_scores asset_risk_scores_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_risk_scores
    ADD CONSTRAINT asset_risk_scores_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: audit_events audit_events_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: collected_files collected_files_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collected_files
    ADD CONSTRAINT collected_files_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: compliance_scores compliance_scores_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_scores
    ADD CONSTRAINT compliance_scores_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.compliance_reports(id) ON DELETE CASCADE;


--
-- Name: endpoint_connections endpoint_connections_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_connections
    ADD CONSTRAINT endpoint_connections_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: endpoint_file_hashes endpoint_file_hashes_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_file_hashes
    ADD CONSTRAINT endpoint_file_hashes_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: endpoint_logs endpoint_logs_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_logs
    ADD CONSTRAINT endpoint_logs_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: endpoint_packages endpoint_packages_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_packages
    ADD CONSTRAINT endpoint_packages_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: endpoint_processes endpoint_processes_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_processes
    ADD CONSTRAINT endpoint_processes_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: endpoint_services endpoint_services_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_services
    ADD CONSTRAINT endpoint_services_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: endpoint_users endpoint_users_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.endpoint_users
    ADD CONSTRAINT endpoint_users_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: hunt_results hunt_results_query_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hunt_results
    ADD CONSTRAINT hunt_results_query_id_fkey FOREIGN KEY (query_id) REFERENCES public.hunt_queries(id) ON DELETE CASCADE;


--
-- Name: incident_events incident_events_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incident_events
    ADD CONSTRAINT incident_events_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id);


--
-- Name: incidents incidents_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: playbook_actions playbook_actions_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_actions
    ADD CONSTRAINT playbook_actions_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.playbooks(id) ON DELETE CASCADE;


--
-- Name: playbook_executions playbook_executions_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.playbooks(id) ON DELETE CASCADE;


--
-- Name: quarantined_files quarantined_files_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_files
    ADD CONSTRAINT quarantined_files_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: registry_entries registry_entries_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registry_entries
    ADD CONSTRAINT registry_entries_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: suppression_state suppression_state_suppression_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppression_state
    ADD CONSTRAINT suppression_state_suppression_id_fkey FOREIGN KEY (suppression_id) REFERENCES public.suppression_rules(id) ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: yara_matches yara_matches_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.yara_matches
    ADD CONSTRAINT yara_matches_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- PostgreSQL database dump complete
--


