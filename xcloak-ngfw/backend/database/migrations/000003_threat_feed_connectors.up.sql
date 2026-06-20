ALTER TABLE threat_feeds
    ADD COLUMN feed_type TEXT NOT NULL DEFAULT 'flatfile',
    ADD COLUMN config JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN threat_feeds.feed_type IS
    'flatfile (existing one-indicator-per-line feeds), otx, misp, or taxii';
COMMENT ON COLUMN threat_feeds.config IS
    'Protocol-specific settings: {"api_key": "..."} for otx/misp, '
    '{"api_key": "...", "collection_id": "...", "username": "...", "password": "..."} for taxii';
