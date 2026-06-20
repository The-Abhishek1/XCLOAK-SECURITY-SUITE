ALTER TABLE threat_feeds
    DROP COLUMN IF EXISTS feed_type,
    DROP COLUMN IF EXISTS config;
