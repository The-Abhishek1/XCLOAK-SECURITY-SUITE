ALTER TABLE agent_releases DROP COLUMN IF EXISTS public_key_fingerprint;
ALTER TABLE agent_releases DROP COLUMN IF EXISTS signature;
