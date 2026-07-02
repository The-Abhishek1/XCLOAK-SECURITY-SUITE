-- Add ed25519 signature field to agent_releases for binary authenticity.
-- The signature is over the raw binary content (base64url-encoded, no padding).
-- Existing rows get NULL — the API rejects unsigned releases when
-- AGENT_RELEASE_REQUIRE_SIGNATURE=true is set in the environment.

ALTER TABLE agent_releases ADD COLUMN IF NOT EXISTS signature TEXT;
ALTER TABLE agent_releases ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT;
