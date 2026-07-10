-- Revert default-privilege grants for future objects only.
-- We intentionally do NOT revoke explicit grants on existing tables because
-- removing them during a rollback would break any running application
-- instance that is already connected as xcloak_app.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES    FROM xcloak_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT                  ON SEQUENCES FROM xcloak_app;
