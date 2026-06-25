ALTER TABLE yara_matches DROP COLUMN IF EXISTS file_hash;
ALTER TABLE yara_matches DROP COLUMN IF EXISTS matched_strings;
