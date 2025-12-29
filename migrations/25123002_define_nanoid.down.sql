BEGIN;

SELECT pg_advisory_xact_lock(25123002);

-- Drop function if it exists
DROP FUNCTION IF EXISTS public.nanoid(integer);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = '__migrations'
  ) THEN
    DELETE FROM public.__migrations WHERE migration_name = '25123002_define_nanoid.up.sql';
  END IF;
END;
$$;

COMMIT;
