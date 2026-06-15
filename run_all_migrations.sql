-- ============================================================
-- XCloak: Run ALL Phase 7-12 migrations in one shot
-- docker exec -i <container_id> psql -U xcloak -d ngfw
-- ============================================================

-- Phase 7: Hunt + Scheduled Tasks + Alert Metrics
CREATE TABLE IF NOT EXISTS hunt_queries (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT DEFAULT '',
  query_type  TEXT NOT NULL,
  query_text  TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  hit_count   INT DEFAULT 0,
  last_run_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hunt_results (
  id         SERIAL PRIMARY KEY,
  query_id   INT NOT NULL REFERENCES hunt_queries(id) ON DELETE CASCADE,
  agent_id   INT NOT NULL,
  result     JSONB NOT NULL,
  found_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scheduled_tasks (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  task_type     TEXT NOT NULL,
  agent_ids     INT[] DEFAULT '{}',
  cron_expr     TEXT NOT NULL,
  payload       JSONB DEFAULT '{}',
  enabled       BOOLEAN DEFAULT TRUE,
  last_run_at   TIMESTAMPTZ,
  next_run_at   TIMESTAMPTZ,
  run_count     INT DEFAULT 0,
  created_by    TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_metrics (
  id           SERIAL PRIMARY KEY,
  bucket_time  TIMESTAMPTZ NOT NULL,
  severity     TEXT NOT NULL,
  count        INT DEFAULT 0,
  UNIQUE(bucket_time, severity)
);

ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS resolved_at  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mttr_seconds BIGINT;

-- Phase 10: Correlation Rules
CREATE TABLE IF NOT EXISTS correlation_rules (
  id              SERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  description     TEXT DEFAULT '',
  severity        TEXT DEFAULT '',
  rule_name       TEXT DEFAULT '',
  mitre_technique TEXT DEFAULT '',
  agent_id        INT DEFAULT 0,
  action          TEXT NOT NULL,
  playbook_id     INT DEFAULT 0,
  enabled         BOOLEAN DEFAULT TRUE,
  match_count     INT DEFAULT 0,
  created_by      TEXT NOT NULL DEFAULT 'admin',
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_endpoint_logs_agent_source
  ON endpoint_logs(agent_id, log_source);

-- Phase 11: Suppression + GeoIP + Health + IOC Blocks
CREATE TABLE IF NOT EXISTS suppression_rules (
  id              SERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  description     TEXT DEFAULT '',
  rule_name       TEXT DEFAULT '',
  agent_id        INT DEFAULT 0,
  severity        TEXT DEFAULT '',
  mitre_technique TEXT DEFAULT '',
  window_minutes  INT DEFAULT 60,
  expires_at      TIMESTAMPTZ,
  enabled         BOOLEAN DEFAULT TRUE,
  match_count     INT DEFAULT 0,
  created_by      TEXT NOT NULL DEFAULT 'admin',
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS suppression_state (
  suppression_id INT NOT NULL REFERENCES suppression_rules(id) ON DELETE CASCADE,
  agent_id       INT NOT NULL,
  rule_name      TEXT NOT NULL,
  last_matched   TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (suppression_id, agent_id, rule_name)
);

CREATE TABLE IF NOT EXISTS geoip_cache (
  ip           TEXT PRIMARY KEY,
  country      TEXT DEFAULT '',
  country_code TEXT DEFAULT '',
  city         TEXT DEFAULT '',
  isp          TEXT DEFAULT '',
  is_proxy     BOOLEAN DEFAULT FALSE,
  fetched_at   TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE endpoint_connections
  ADD COLUMN IF NOT EXISTS country      TEXT DEFAULT '',
  ADD COLUMN IF NOT EXISTS country_code TEXT DEFAULT '',
  ADD COLUMN IF NOT EXISTS is_proxy     BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS agent_health (
  agent_id          INT PRIMARY KEY,
  health_score      INT DEFAULT 100,
  health_status     TEXT DEFAULT 'healthy',
  last_heartbeat    TIMESTAMPTZ,
  heartbeat_gap_s   INT DEFAULT 0,
  task_success_rate FLOAT DEFAULT 1.0,
  alert_rate_1h     INT DEFAULT 0,
  computed_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ioc_firewall_blocks (
  id         SERIAL PRIMARY KEY,
  ioc_id     INT NOT NULL,
  indicator  TEXT NOT NULL,
  agent_id   INT NOT NULL,
  rule_id    INT,
  blocked_at TIMESTAMPTZ DEFAULT now()
);

-- Phase 12: Integrations + Webhooks + Install Tokens
CREATE TABLE IF NOT EXISTS integrations (
  id         SERIAL PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  enabled    BOOLEAN DEFAULT FALSE,
  config     JSONB DEFAULT '{}',
  updated_at TIMESTAMPTZ DEFAULT now(),
  updated_by TEXT DEFAULT 'admin'
);

INSERT INTO integrations (name, enabled, config) VALUES
  ('slack',     FALSE, '{"webhook_url":"","channel":"#security","mention_on_critical":true}'),
  ('webhook',   FALSE, '{"url":"","secret":"","events":["critical_alert","incident_created"]}'),
  ('email',     FALSE, '{"smtp_host":"","smtp_port":587,"from":"","to":[],"tls":true}'),
  ('pagerduty', FALSE, '{"integration_key":"","severity_threshold":"high"}')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id           SERIAL PRIMARY KEY,
  integration  TEXT NOT NULL,
  event_type   TEXT NOT NULL,
  payload      JSONB DEFAULT '{}',
  status_code  INT,
  success      BOOLEAN DEFAULT FALSE,
  error_msg    TEXT DEFAULT '',
  delivered_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_install_tokens (
  id         SERIAL PRIMARY KEY,
  token      TEXT NOT NULL UNIQUE,
  label      TEXT DEFAULT '',
  used       BOOLEAN DEFAULT FALSE,
  created_by TEXT NOT NULL DEFAULT 'admin',
  expires_at TIMESTAMPTZ DEFAULT now() + INTERVAL '24 hours',
  created_at TIMESTAMPTZ DEFAULT now()
);

SELECT 'All migrations applied successfully' AS status;
