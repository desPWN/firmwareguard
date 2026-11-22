-- Executed on fresh initdb
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'firmwareguard') THEN
    CREATE ROLE firmwareguard WITH LOGIN SUPERUSER PASSWORD 'firmwareguard';
  END IF;
END
$$;
