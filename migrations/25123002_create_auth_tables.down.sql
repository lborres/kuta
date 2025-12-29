BEGIN;

SELECT pg_advisory_xact_lock(25123002);

DROP TABLE IF EXISTS public.sessions;
DROP TABLE IF EXISTS public.accounts;
DROP TABLE IF EXISTS public.users;
DROP DOMAIN public.nanoid;

COMMIT;
