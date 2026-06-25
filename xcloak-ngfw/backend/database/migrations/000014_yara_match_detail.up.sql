-- The agent now parses real `yara -s -m` output (matched strings + rule
-- meta) instead of hardcoding severity/description and dropping everything
-- but rule name + file path. These columns carry that detail through.
ALTER TABLE yara_matches ADD COLUMN matched_strings TEXT NOT NULL DEFAULT '[]';
ALTER TABLE yara_matches ADD COLUMN file_hash TEXT NOT NULL DEFAULT '';
