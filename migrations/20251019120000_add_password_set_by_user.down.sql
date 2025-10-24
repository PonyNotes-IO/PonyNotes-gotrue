-- Rollback migration: Remove password_set_by_user column

-- Drop the index
DROP INDEX IF EXISTS {{ index .Options "Namespace" }}.users_password_set_by_user_idx;

-- Drop the column
ALTER TABLE {{ index .Options "Namespace" }}.users 
DROP COLUMN IF EXISTS password_set_by_user;



