BEGIN;

SELECT pg_advisory_xact_lock(25123003);

DROP TABLE IF EXISTS public.sessions;
DROP TABLE IF EXISTS public.accounts;
DROP TABLE IF EXISTS public.users;
DROP DOMAIN public.nanoid;

DELETE FROM public.__migrations WHERE migration_name = '25123003_create_auth_tables.up.sql';

COMMIT;
