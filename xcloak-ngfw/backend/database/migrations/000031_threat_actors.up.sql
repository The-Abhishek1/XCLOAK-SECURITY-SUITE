CREATE TABLE IF NOT EXISTS threat_actors (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    aliases         TEXT[] NOT NULL DEFAULT '{}',
    origin_country  VARCHAR(100) NOT NULL DEFAULT '',
    motivation      VARCHAR(100) NOT NULL DEFAULT '', -- espionage, financial, hacktivism, destructive
    sophistication  VARCHAR(30)  NOT NULL DEFAULT 'medium', -- low/medium/high/nation-state
    description     TEXT NOT NULL DEFAULT '',
    targeted_sectors TEXT[] NOT NULL DEFAULT '{}',
    mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
    is_builtin      BOOLEAN NOT NULL DEFAULT false, -- true = seeded, not user-created
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS actor_alert_tags (
    id          SERIAL PRIMARY KEY,
    actor_id    INTEGER NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    confidence  INTEGER NOT NULL DEFAULT 50, -- 0-100
    matched_technique VARCHAR(50) NOT NULL DEFAULT '',
    tagged_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (actor_id, alert_id)
);

CREATE TABLE IF NOT EXISTS playbook_recommendations (
    id          SERIAL PRIMARY KEY,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    score       INTEGER NOT NULL DEFAULT 0, -- 0-100 relevance
    reason      TEXT NOT NULL DEFAULT '',
    executed    BOOLEAN NOT NULL DEFAULT false,
    executed_by VARCHAR(100) NOT NULL DEFAULT '',
    executed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (alert_id, playbook_id)
);

CREATE TABLE IF NOT EXISTS playbook_outcome_feedback (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_rule_name VARCHAR(255) NOT NULL DEFAULT '',
    mitre_technique VARCHAR(50) NOT NULL DEFAULT '',
    playbook_id     INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    was_effective   BOOLEAN NOT NULL DEFAULT true,
    feedback_by     VARCHAR(100) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_actors_tenant   ON threat_actors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_actor_tags_alert        ON actor_alert_tags(alert_id);
CREATE INDEX IF NOT EXISTS idx_actor_tags_tenant       ON actor_alert_tags(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pb_recs_alert           ON playbook_recommendations(alert_id);
CREATE INDEX IF NOT EXISTS idx_pb_recs_tenant          ON playbook_recommendations(tenant_id);
