BEGIN;

SELECT pg_advisory_xact_lock(25123001);

DROP FUNCTION IF EXISTS public.nanoid(integer);

COMMIT;
