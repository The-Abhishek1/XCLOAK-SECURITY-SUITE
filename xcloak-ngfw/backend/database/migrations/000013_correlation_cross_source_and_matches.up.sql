-- Extends correlation rules beyond alerts-only conditions, and adds a real
-- per-firing audit trail (previously a rule match only incremented a bare
-- counter, with no record of which alert/stages caused it).
--
-- source_type values: 'alert' (default, fully backward compatible) |
-- 'vulnerability' | 'network_connect' | 'risk_score'. condition_value is a
-- generic pattern/threshold string used only when source_type != 'alert'
-- for simple/event_count rules — same idea as stages' existing generic
-- rule_name_pattern column, just at the rule level.
ALTER TABLE correlation_rules ADD COLUMN source_type TEXT NOT NULL DEFAULT 'alert';
ALTER TABLE correlation_rules ADD COLUMN condition_value TEXT NOT NULL DEFAULT '';
ALTER TABLE correlation_rule_stages ADD COLUMN source_type TEXT NOT NULL DEFAULT 'alert';

CREATE TABLE correlation_matches (
    id BIGSERIAL PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES correlation_rules(id) ON DELETE CASCADE,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    trigger_alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    confidence INT NOT NULL DEFAULT 50,
    detail TEXT NOT NULL DEFAULT '',
    matched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_correlation_matches_rule_id ON correlation_matches (rule_id, matched_at DESC);
CREATE INDEX idx_correlation_matches_tenant_id ON correlation_matches (tenant_id, matched_at DESC);
