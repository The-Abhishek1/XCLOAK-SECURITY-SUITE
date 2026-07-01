-- Conditional playbook engine: branch routing, step naming, loop-over,
-- stop-on-failure. Closes the XSOAR-style branching gap.

ALTER TABLE playbook_actions
    ADD COLUMN IF NOT EXISTS step_name       TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS goto_on_success TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS goto_on_failure TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS stop_on_failure BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS loop_over       TEXT    NOT NULL DEFAULT '';

-- Record the step_name in results so execution traces are human-readable.
ALTER TABLE playbook_step_results
    ADD COLUMN IF NOT EXISTS step_name  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS loop_item  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS goto_taken TEXT NOT NULL DEFAULT '';
