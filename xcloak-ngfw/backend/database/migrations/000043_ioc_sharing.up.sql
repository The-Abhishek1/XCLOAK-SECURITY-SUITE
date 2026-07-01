-- IOC propagation: track where an IOC came from and whether it can be shared
-- across tenants on the platform. Feed-sourced and manually-managed IOCs both
-- get a source column so the UI can show provenance.

ALTER TABLE iocs
    ADD COLUMN IF NOT EXISTS source       TEXT    NOT NULL DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS shareable    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS platform_ioc BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_iocs_shareable ON iocs (shareable, severity) WHERE shareable = TRUE AND enabled = TRUE;

-- Track propagation history so we don't re-propagate the same IOC twice.
CREATE TABLE IF NOT EXISTS ioc_propagations (
    id              SERIAL       PRIMARY KEY,
    source_tenant   INTEGER      NOT NULL,
    dest_tenant     INTEGER      NOT NULL,
    indicator       TEXT         NOT NULL,
    ioc_type        TEXT         NOT NULL,
    severity        TEXT         NOT NULL,
    propagated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (source_tenant, dest_tenant, indicator)
);
CREATE INDEX IF NOT EXISTS idx_iocprop_dest ON ioc_propagations (dest_tenant, propagated_at);

-- Per-tenant opt-out flag. TRUE = participate in cross-tenant IOC sharing.
-- Default FALSE: tenants must explicitly opt in to receive platform IOCs.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS ioc_sharing_enabled BOOLEAN NOT NULL DEFAULT FALSE;
