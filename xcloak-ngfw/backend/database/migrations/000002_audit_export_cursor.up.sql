CREATE TABLE audit_export_cursor (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_exported_id INTEGER NOT NULL DEFAULT 0,
    last_exported_at TIMESTAMPTZ,
    last_object_key TEXT
);

INSERT INTO audit_export_cursor (id, last_exported_id) VALUES (1, 0);
