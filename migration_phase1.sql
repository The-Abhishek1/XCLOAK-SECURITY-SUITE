-- ============================================================
-- XCloak Phase 1: Detection Depth — Migration
-- Run via: docker exec -i <postgres_container> psql -U xcloak -d ngfw
-- ============================================================

-- ── Sigma-lite: selections + condition expression ──────────
ALTER TABLE sigma_rules
  ADD COLUMN IF NOT EXISTS selections JSONB DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS condition  TEXT  DEFAULT '';

-- Backfill existing keyword-only rules into the new format:
-- selections = {"selection1": [...keywords]}, condition = "selection1"
UPDATE sigma_rules
SET
  selections = jsonb_build_object('selection1', keywords),
  condition  = 'selection1'
WHERE (selections = '{}'::jsonb OR selections IS NULL)
  AND condition = ''
  AND keywords IS NOT NULL
  AND jsonb_array_length(keywords) > 0;

-- ── YARA rule management ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS yara_rules (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  description   TEXT DEFAULT '',
  rule_content  TEXT NOT NULL,
  enabled       BOOLEAN DEFAULT true,
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- Seed the existing hardcoded rule so it's manageable from the UI
INSERT INTO yara_rules (name, description, rule_content, enabled)
SELECT
  'SuspiciousShell',
  'Detects reverse shell indicators (bash -i, /dev/tcp)',
  'rule SuspiciousShell
{
    strings:
        $cmd1 = "bash -i"
        $cmd2 = "/dev/tcp"

    condition:
        any of them
}',
  true
WHERE NOT EXISTS (SELECT 1 FROM yara_rules WHERE name = 'SuspiciousShell');

-- ── Threat feed sync tracking (last_sync already exists) ────
-- Nothing else needed — threat_feeds.last_sync column already present.
