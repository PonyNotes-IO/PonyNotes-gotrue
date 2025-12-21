-- Migration: create auth.sign_in_logs table for recording per-login events
-- Use pgcrypto's gen_random_uuid() for better compatibility in many environments.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Note: this table is created in the 'auth' schema to follow gotrue's auth objects.
CREATE TABLE IF NOT EXISTS auth.sign_in_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_uuid uuid NULL,
  user_uid bigint NULL,
  provider text NULL,
  third_party_id text NULL,
  ip_address inet NULL,
  country text NULL,
  region text NULL,
  city text NULL,
  user_agent text NULL,
  success boolean NOT NULL DEFAULT true,
  error_reason text NULL,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS sign_in_logs_user_uuid_idx ON auth.sign_in_logs (user_uuid, created_at DESC);
CREATE INDEX IF NOT EXISTS sign_in_logs_user_uid_idx ON auth.sign_in_logs (user_uid, created_at DESC);
CREATE INDEX IF NOT EXISTS sign_in_logs_created_at_idx ON auth.sign_in_logs (created_at);


