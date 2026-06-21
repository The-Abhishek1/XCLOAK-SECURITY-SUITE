-- Custom roles with fine-grained permissions, sitting alongside (not
-- replacing) the built-in admin/analyst/viewer roles. A user's existing
-- `role` column can hold a custom role's name instead of a built-in one —
-- middleware.RequirePermission resolves it against this table.
CREATE TABLE custom_roles (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, name)
);
