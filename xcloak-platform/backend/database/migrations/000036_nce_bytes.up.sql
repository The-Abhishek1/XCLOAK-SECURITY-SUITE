-- Add transfer volume columns to network_connect_events so the eBPF agent
-- can report bytes sent/received per connection when available.
-- These default to 0 so existing rows are unaffected.
ALTER TABLE network_connect_events
    ADD COLUMN IF NOT EXISTS bytes_sent BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS bytes_recv BIGINT NOT NULL DEFAULT 0;
