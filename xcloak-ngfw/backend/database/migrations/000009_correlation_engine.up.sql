-- Upgrades correlation_rules from single-alert matching to real
-- time-windowed correlation, modeled on upstream Sigma's correlation
-- rule types (event_count / temporal / temporal_ordered). value_count
-- (distinct-field cardinality) is deliberately not implemented — the
-- alerts table has no structured per-alert field data to count over,
-- only rule_name/severity/mitre_*, so faking it would mean a feature
-- that looks real but silently can't do what it claims.
--
-- correlation_type:
--   'simple'           — existing single-alert condition match (default,
--                         fully backward compatible with every existing row)
--   'event_count'      — N+ alerts matching this rule's own conditions
--                         within window_minutes for the same agent
--   'temporal'         — every stage in correlation_rule_stages has at
--                         least one matching alert within window_minutes
--                         for the same agent, any order
--   'temporal_ordered' — same as temporal, but stages must occur in
--                         non-decreasing time order (a real attack chain:
--                         recon, then exploitation, then persistence, ...)

ALTER TABLE correlation_rules ADD COLUMN correlation_type TEXT NOT NULL DEFAULT 'simple';
ALTER TABLE correlation_rules ADD COLUMN window_minutes INT NOT NULL DEFAULT 0;
ALTER TABLE correlation_rules ADD COLUMN threshold INT NOT NULL DEFAULT 1;

CREATE TABLE correlation_rule_stages (
    id BIGSERIAL PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES correlation_rules(id) ON DELETE CASCADE,
    stage_order INT NOT NULL,
    rule_name_pattern TEXT NOT NULL
);

CREATE INDEX idx_correlation_rule_stages_rule_id ON correlation_rule_stages (rule_id);

-- Speeds up the windowed lookups EvaluateCorrelationRules now runs
-- (per-agent, recent-time-range scans of the alerts table).
CREATE INDEX IF NOT EXISTS idx_alerts_agent_created_at ON alerts (agent_id, created_at);
