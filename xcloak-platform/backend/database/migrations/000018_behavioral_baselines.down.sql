DROP TABLE IF EXISTS agent_anomaly_scores;
DROP TABLE IF EXISTS agent_behavior_baselines;

ALTER TABLE anomaly_findings
    DROP COLUMN IF EXISTS score,
    DROP COLUMN IF EXISTS acknowledged,
    DROP COLUMN IF EXISTS source;
