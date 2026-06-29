ALTER TABLE network_connect_events
    DROP COLUMN IF EXISTS bytes_sent,
    DROP COLUMN IF EXISTS bytes_recv;
