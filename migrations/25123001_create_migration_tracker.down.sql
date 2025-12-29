-- Rollback: drop auth tables
DROP TABLE IF EXISTS public.__migrations;

SELECT pg_advisory_xact_lock(25123001);
