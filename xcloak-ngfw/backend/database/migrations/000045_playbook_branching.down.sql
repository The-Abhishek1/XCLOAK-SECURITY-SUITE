ALTER TABLE playbook_step_results DROP COLUMN IF EXISTS goto_taken;
ALTER TABLE playbook_step_results DROP COLUMN IF EXISTS loop_item;
ALTER TABLE playbook_step_results DROP COLUMN IF EXISTS step_name;
ALTER TABLE playbook_actions DROP COLUMN IF EXISTS loop_over;
ALTER TABLE playbook_actions DROP COLUMN IF EXISTS stop_on_failure;
ALTER TABLE playbook_actions DROP COLUMN IF EXISTS goto_on_failure;
ALTER TABLE playbook_actions DROP COLUMN IF EXISTS goto_on_success;
ALTER TABLE playbook_actions DROP COLUMN IF EXISTS step_name;
