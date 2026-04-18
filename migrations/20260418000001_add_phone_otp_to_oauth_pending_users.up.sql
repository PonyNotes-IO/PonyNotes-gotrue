-- 为 oauth_pending_users 表添加手机 OTP 存储字段
-- 用于"手机号未注册"场景下的 OTP 验证（无法使用 one_time_tokens，因为该表要求 user_id 外键约束）
alter table {{ index .Options "Namespace" }}.oauth_pending_users
    add column if not exists phone_otp_hash text,
    add column if not exists phone_otp_sent_at timestamptz;

comment on column {{ index .Options "Namespace" }}.oauth_pending_users.phone_otp_hash is 'OTP hash for phone verification in pending OAuth flow (phone not yet registered)';
comment on column {{ index .Options "Namespace" }}.oauth_pending_users.phone_otp_sent_at is 'Timestamp when phone OTP was sent, used for expiry validation';
