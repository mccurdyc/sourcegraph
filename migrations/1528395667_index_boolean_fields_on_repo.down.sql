BEGIN;

DROP INDEX IF EXISTS repo_private;
DROP INDEX IF EXISTS repo_fork;
DROP INDEX IF EXISTS repo_archived;

COMMIT;