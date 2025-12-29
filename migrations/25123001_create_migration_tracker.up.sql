BEGIN;

SELECT pg_advisory_xact_lock(25123001);

CREATE TABLE IF NOT EXISTS public.__migrations (
  migration_name text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

COMMIT;
