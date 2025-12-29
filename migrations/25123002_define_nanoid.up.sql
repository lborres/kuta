-- creates a nanoid() function within postgres
-- should only be used sparingly. DO NOT USE for high volume.
-- prefer the api server's nanoid generation

BEGIN;
SELECT pg_advisory_xact_lock(25123002);

-- ensure crypto is available
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION public.gen_random_nanoid(len integer DEFAULT 22)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  alphabet text := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  alphabet_len int := length(alphabet);
  k int := 1;
  mask int;
  step int;
  result text := '';
  buffer bytea;
  i int;
  b int;
BEGIN
  IF len IS NULL OR len <= 0 THEN
    len := 22;
  END IF;

  -- compute mask = smallest (2^k - 1) >= alphabet_len-1
  WHILE ((1 << k) - 1) < (alphabet_len - 1) LOOP
    k := k + 1;
    IF k > 16 THEN EXIT; END IF; -- safe guard
  END LOOP;
  mask := (1 << k) - 1;

  -- step heuristic similar to JS/Go NanoID
  step := CEIL(1.6 * mask * len::numeric / alphabet_len)::int;
  IF step < 1 THEN step := 1; END IF;

  WHILE length(result) < len LOOP
    buffer := gen_random_bytes(step);
    i := 0;
    WHILE i < length(buffer) LOOP
      b := get_byte(buffer, i) & mask;
      IF b < alphabet_len THEN
        result := result || substring(alphabet FROM b+1 FOR 1);
        IF length(result) >= len THEN
          EXIT;
        END IF;
      END IF;
      i := i + 1;
    END LOOP;
  END LOOP;

  RETURN result;
END;
$$;

-- Record this migration in the tracker if the tracker table exists (best-effort)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = '__migrations'
  ) THEN
    INSERT INTO public.__migrations (migration_name, applied_at)
    VALUES ('25123002_define_nanoid.up.sql', now())
    ON CONFLICT (migration_name) DO NOTHING;
  END IF;
END;
$$;

COMMIT;