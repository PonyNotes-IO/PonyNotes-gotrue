-- Stores OAuth pending users awaiting phone binding
create table if not exists {{ index .Options "Namespace" }}.oauth_pending_users(
    id uuid primary key,
    platform text not null,
    provider_id text not null,
    user_meta jsonb not null,
    pending_token text not null,
    expires_at timestamptz not null,
    created_at timestamptz null default now()
);

-- Index for looking up by pending_token
create index if not exists idx_oauth_pending_users_token on {{ index .Options "Namespace" }}.oauth_pending_users(pending_token);

-- Index for looking up by platform + provider_id (in case we need to query)
create index if not exists idx_oauth_pending_users_platform on {{ index .Options "Namespace" }}.oauth_pending_users(platform, provider_id);

-- Index for cleanup expired records
create index if not exists idx_oauth_pending_users_expires on {{ index .Options "Namespace" }}.oauth_pending_users(expires_at);

comment on table {{ index .Options "Namespace" }}.oauth_pending_users is 'Stores OAuth pending users awaiting phone binding. Deleted after successful bind or expiration.';
