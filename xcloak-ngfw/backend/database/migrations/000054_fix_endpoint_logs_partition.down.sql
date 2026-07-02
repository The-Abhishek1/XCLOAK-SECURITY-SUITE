-- Reverting this migration would undo the partitioning, which is destructive.
-- Left intentionally empty — use the 052 down migration to fully revert.
SELECT 1;
