-- Treehammock canonical greenfield PostgreSQL baseline.
--
-- This project is not deployed anywhere yet, so this file intentionally creates
-- the final development schema directly. No compatibility/backfill layer is included.
-- Repository-facing routines are row-returning PostgreSQL functions invoked as
-- `select * from function(@params...)`.

create extension if not exists pgcrypto;

create table if not exists accounts(
    account_id uuid primary key,
    email_address text not null,
    username text null,
    hashed_password bytea not null default decode(repeat('00', 128), 'hex'),
    created_on timestamp with time zone not null default now(),
    web_key text not null default gen_random_uuid()::text,
    verify_status smallint not null default 0,
    salt_one bytea not null default decode(repeat('00', 64), 'hex'),
    siv bytea not null default decode(repeat('00', 32), 'hex'),
    nonce bytea not null default decode(repeat('00', 16), 'hex'),
    unlock_when timestamp with time zone null,
    login_failures smallint not null default 0,
    features smallint not null default 0,
    two_factor_access_token text null,
    two_factor_auth_method smallint not null default 0,
    two_auth_usage smallint null,
    country smallint not null default 0,
    cut_off timestamp with time zone null,
    locked_down smallint null,
    security_stamp uuid not null default gen_random_uuid(),
    constraint ck_accounts_login_failures_nonnegative check (login_failures >= 0)
);

create unique index if not exists ux_accounts_email_address_lower
    on accounts(lower(email_address));

create unique index if not exists ux_accounts_username_lower
    on accounts(lower(username))
    where username is not null;

create unique index if not exists ux_accounts_web_key
    on accounts(web_key);

create index if not exists ix_accounts_security_stamp
    on accounts(account_id, security_stamp);

create table if not exists account_verifications(
    verification_index bigint generated always as identity primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    verify_key_hash text not null,
    verify_status smallint not null default 0,
    sent_when timestamp with time zone null,
    expiration interval null,
    created_on timestamp with time zone not null default now()
);

create unique index if not exists ux_account_verifications_verify_key_hash
    on account_verifications(verify_key_hash);

create table if not exists account_email_change_requests(
    account_id uuid primary key references accounts(account_id) on delete cascade,
    new_email_address text not null,
    verify_key_hash text not null unique,
    requested_at timestamp with time zone not null default now(),
    expiration timestamp with time zone not null,
    account_security_stamp uuid not null
);

create unique index if not exists ux_account_email_change_new_email_lower
    on account_email_change_requests(lower(new_email_address));

create index if not exists ix_account_email_change_expiration
    on account_email_change_requests(expiration);

create index if not exists ix_account_verifications_account_status
    on account_verifications(account_id, verify_status);

create table if not exists sessions(
    access_token_hash text primary key,
    session_id uuid not null default gen_random_uuid(),
    account_id uuid not null references accounts(account_id) on delete cascade,
    refresh_token bytea not null default decode(repeat('00', 64), 'hex'),
    refreshes smallint not null default 0,
    refresh_limit smallint not null default 0,
    created_on timestamp with time zone not null default now(),
    session_lifespan interval null,
    access_expiration timestamp with time zone not null,
    session_expiration timestamp with time zone not null,
    cut_off timestamp with time zone null,
    features smallint not null default 0,
    security_stamp uuid not null default gen_random_uuid(),
    account_security_stamp uuid not null,
    constraint ck_sessions_refreshes_nonnegative check (refreshes >= 0),
    constraint ck_sessions_refresh_limit_nonnegative check (refresh_limit >= 0),
    constraint ck_sessions_expiration_order check (session_expiration >= created_on),
    constraint ck_sessions_access_not_after_session check (access_expiration <= session_expiration)
);

create unique index if not exists ux_sessions_session_id
    on sessions(session_id);

create index if not exists ix_sessions_account_session_id
    on sessions(account_id, session_id);

create index if not exists ix_sessions_account_active
    on sessions(account_id, session_expiration desc, created_on desc);

create index if not exists ix_sessions_account_stamp
    on sessions(account_id, account_security_stamp);

create index if not exists ix_sessions_expiration
    on sessions(session_expiration);


create table if not exists account_sensitive_action_tokens(
    token_id uuid primary key default gen_random_uuid(),
    account_id uuid not null references accounts(account_id) on delete cascade,
    session_binding_hash text not null,
    token_hash text not null,
    purpose smallint not null,
    created_on timestamp with time zone not null default now(),
    expiration timestamp with time zone not null,
    consumed_on timestamp with time zone null,
    account_security_stamp uuid not null,
    attempts integer not null default 0,
    constraint ck_sensitive_action_purpose_positive check (purpose > 0),
    constraint ck_sensitive_action_expiration_order check (expiration > created_on),
    constraint ck_sensitive_action_attempts_nonnegative check (attempts >= 0)
);

create unique index if not exists ux_sensitive_action_token_hash
    on account_sensitive_action_tokens(token_hash);

create index if not exists ix_sensitive_action_account_session_purpose
    on account_sensitive_action_tokens(account_id, session_binding_hash, purpose, expiration desc);

create index if not exists ix_sensitive_action_expiration
    on account_sensitive_action_tokens(expiration);

create table if not exists two_factor_authentications(
    two_factor_index smallint not null,
    account_id uuid not null references accounts(account_id) on delete cascade,
    token text null,
    auth_id text null,
    created_on timestamp with time zone not null default now(),
    lifespan interval null,
    expiration timestamp with time zone null,
    method smallint not null,
    verified boolean not null default false,
    priority smallint not null default 0,
    country smallint null,
    email_address text null,
    phone_number text null,
    phone_country_code text null,
    required boolean not null default false,
    totp_secret_ciphertext bytea null,
    totp_secret_nonce bytea null,
    totp_secret_tag bytea null,
    totp_secret_version integer not null default 1,
    totp_last_used_step bigint null,
    totp_provider_type smallint not null default 1,
    totp_provider_enrollment_id text null,
    totp_provider_account_binding_hash text null,
    setup_attempts smallint not null default 0,
    revoked_at timestamp with time zone null,
    revoked_reason text null,
    constraint ck_two_factor_setup_attempts_nonnegative check(setup_attempts >= 0),
    constraint ck_two_factor_totp_provider_type check(totp_provider_type in (1, 2)),
    primary key(account_id, two_factor_index)
);

create index if not exists ix_two_factor_account_verified
    on two_factor_authentications(account_id, verified, priority);

create unique index if not exists ux_two_factor_one_pending_setup_per_account
    on two_factor_authentications(account_id)
    where verified = false and revoked_at is null;

create unique index if not exists ux_two_factor_one_verified_email_per_account
    on two_factor_authentications(account_id)
    where verified = true and method = 1 and revoked_at is null;

create unique index if not exists ux_two_factor_one_verified_sms_per_account
    on two_factor_authentications(account_id)
    where verified = true and method = 2 and revoked_at is null;

create unique index if not exists ux_two_factor_one_verified_authenticator_app
    on two_factor_authentications(account_id)
    where verified = true and method = 3 and revoked_at is null;


create table if not exists pending_two_factor_sessions(
    pre_auth_access_token_hash text primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    account_security_stamp uuid not null,
    two_auth_usage smallint null,
    created_on timestamp with time zone not null default now(),
    expiration timestamp with time zone not null,
    selected_two_factor_configuration smallint null,
    state smallint not null default 1,
    available_configurations smallint[] not null default array[]::smallint[],
    required_methods smallint[] not null default array[]::smallint[],
    completed_methods smallint[] not null default array[]::smallint[],
    current_expected_method smallint null,
    selected_at timestamp with time zone null,
    completed_at timestamp with time zone null,
    challenged_method smallint null,
    chosen_destination smallint null,
    challenge_code_hash text null,
    challenge_provider_transaction_id text null,
    challenge_expiration timestamp with time zone null,
    challenge_attempts smallint not null default 0,
    challenge_resends smallint not null default 0,
    next_challenge_allowed_at timestamp with time zone null,
    constraint ck_pending_two_factor_selected_configuration check(selected_two_factor_configuration is null or selected_two_factor_configuration between 0 and 6),
    constraint ck_pending_two_factor_state_range check(state between 1 and 7),
    constraint ck_pending_two_factor_current_expected_method check(current_expected_method is null or current_expected_method between 1 and 3),
    constraint ck_pending_two_factor_attempts_nonnegative check(challenge_attempts >= 0),
    constraint ck_pending_two_factor_resends_nonnegative check(challenge_resends >= 0)
);

create index if not exists ix_pending_two_factor_account_current
    on pending_two_factor_sessions(account_id, account_security_stamp, expiration desc);


create or replace function resolve_available_twofactor_configurations(p_accountId uuid)
returns smallint[]
language sql
stable
as $$
    with usable_methods as (
        select distinct t.method::smallint as method
          from two_factor_authentications t
          join accounts a on a.account_id = t.account_id
         where t.account_id = p_accountId
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > now())
           and (
                (t.method = 1 and nullif(trim(a.email_address), '') is not null)
                or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
                or (
                    t.method = 3
                    and t.revoked_at is null
                    and t.totp_provider_type = 1
                    and t.totp_secret_ciphertext is not null
                    and octet_length(t.totp_secret_ciphertext) > 0
                    and t.totp_secret_nonce is not null
                    and octet_length(t.totp_secret_nonce) > 0
                    and t.totp_secret_tag is not null
                    and octet_length(t.totp_secret_tag) > 0
                    and coalesce(t.totp_secret_version, 0) > 0
                )
           )
    ), flags as (
        select coalesce(bool_or(method = 1), false) as has_email,
               coalesce(bool_or(method = 2), false) as has_sms,
               coalesce(bool_or(method = 3), false) as has_authenticator_app
          from usable_methods
    )
    select coalesce(array_agg(option_row.configuration order by option_row.ordinal), array[]::smallint[])
      from flags
      cross join lateral (
        values
            (1, 1::smallint, flags.has_sms),
            (2, 2::smallint, flags.has_email),
            (3, 3::smallint, flags.has_authenticator_app),
            (4, 4::smallint, flags.has_sms and flags.has_authenticator_app),
            (5, 5::smallint, flags.has_email and flags.has_authenticator_app)
      ) as option_row(ordinal, configuration, is_available)
     where option_row.is_available;
$$;

create table if not exists account_recoveries(
    account_id uuid not null references accounts(account_id) on delete cascade,
    created_on timestamp with time zone not null default now(),
    status smallint not null,
    topic smallint not null,
    expiration timestamp with time zone not null,
    token_hash text not null,
    method smallint not null,
    lockout_security_stamp uuid not null,
    lockout_unlock_when timestamp with time zone not null,
    primary key(account_id, token_hash)
);

create unique index if not exists ux_account_recoveries_token_hash
    on account_recoveries(token_hash);


create table if not exists password_reset_requests(
    password_reset_request_id uuid primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    method text not null,
    delivery_channel text null,
    key_code_hash text null,
    key_code_hash_version integer null,
    destination_fingerprint text not null,
    destination_masked text not null,
    requires_key_code boolean not null default true,
    requires_totp boolean not null default false,
    created_at timestamp with time zone not null default now(),
    expires_at timestamp with time zone not null,
    consumed_at timestamp with time zone null,
    cancelled_at timestamp with time zone null,
    attempt_count integer not null default 0,
    max_attempts integer not null,
    requested_by_ip inet null,
    requested_by_user_agent text null,
    account_security_stamp_at_request uuid not null,
    constraint ck_password_reset_method check (
        method in ('sms', 'email')
    ),
    constraint ck_password_reset_delivery_channel check (
        delivery_channel is null or delivery_channel in ('email', 'sms')
    ),
    constraint ck_password_reset_key_code_hash_not_blank check (key_code_hash is null or length(btrim(key_code_hash)) > 0),
    constraint ck_password_reset_key_code_hash_version_positive check (key_code_hash_version is null or key_code_hash_version > 0),
    constraint ck_password_reset_destination_fingerprint_not_blank check (length(btrim(destination_fingerprint)) > 0),
    constraint ck_password_reset_destination_masked_not_blank check (length(btrim(destination_masked)) > 0),
    constraint ck_password_reset_attempt_count_nonnegative check (attempt_count >= 0),
    constraint ck_password_reset_max_attempts_positive check (max_attempts > 0),
    constraint ck_password_reset_expiration check (expires_at > created_at),
    constraint ck_password_reset_consumed_after_created check (consumed_at is null or consumed_at >= created_at),
    constraint ck_password_reset_cancelled_after_created check (cancelled_at is null or cancelled_at >= created_at),
    constraint ck_password_reset_method_requirements check (
        (method = 'sms' and delivery_channel = 'sms' and requires_key_code = true and requires_totp = false and key_code_hash is not null and key_code_hash_version is not null)
        or
        (method = 'email' and delivery_channel = 'email' and requires_key_code = true and requires_totp = false and key_code_hash is not null and key_code_hash_version is not null)
    )
);

create unique index if not exists ux_password_reset_requests_one_active_per_account
    on password_reset_requests(account_id)
    where consumed_at is null
      and cancelled_at is null;

create index if not exists ix_password_reset_requests_account_created
    on password_reset_requests(account_id, created_at desc);

create index if not exists ix_password_reset_requests_expires_at
    on password_reset_requests(expires_at);

create index if not exists ix_password_reset_requests_destination_fingerprint_active
    on password_reset_requests(destination_fingerprint)
    where consumed_at is null
      and cancelled_at is null;

create table if not exists pending_password_reset_sessions(
    reset_access_token_hash text primary key,
    password_reset_request_id uuid null references password_reset_requests(password_reset_request_id) on delete cascade,
    account_id uuid not null references accounts(account_id) on delete cascade,
    bootstrap_proof smallint not null,
    state smallint not null,
    available_configurations smallint[] not null default array[]::smallint[],
    selected_two_factor_configuration smallint null,
    required_methods smallint[] not null default array[]::smallint[],
    completed_methods smallint[] not null default array[]::smallint[],
    current_expected_method smallint null,
    challenge_code_hash text null,
    challenge_expiration timestamp with time zone null,
    challenge_attempts integer not null default 0,
    challenge_resends integer not null default 0,
    next_challenge_allowed_at timestamp with time zone null,
    created_on timestamp with time zone not null default now(),
    expires_at timestamp with time zone not null,
    selected_at timestamp with time zone null,
    two_factor_completed_at timestamp with time zone null,
    password_changed_at timestamp with time zone null,
    revoked_at timestamp with time zone null,
    revoked_reason text null,
    constraint ck_pending_password_reset_hash_not_blank check(length(btrim(reset_access_token_hash)) > 0),
    constraint ck_pending_password_reset_bootstrap_proof check(bootstrap_proof between 0 and 3),
    constraint ck_pending_password_reset_state check(state between 1 and 10),
    constraint ck_pending_password_reset_selected_configuration check(selected_two_factor_configuration is null or selected_two_factor_configuration between 0 and 6),
    constraint ck_pending_password_reset_current_expected_method check(current_expected_method is null or current_expected_method between 1 and 3),
    constraint ck_pending_password_reset_attempts_nonnegative check(challenge_attempts >= 0),
    constraint ck_pending_password_reset_resends_nonnegative check(challenge_resends >= 0),
    constraint ck_pending_password_reset_expiration check(expires_at > created_on),
    constraint ck_pending_password_reset_revoked_reason check(revoked_reason is null or length(btrim(revoked_reason)) > 0)
);

create index if not exists ix_pending_password_reset_sessions_account_current
    on pending_password_reset_sessions(account_id, expires_at desc)
    where revoked_at is null;

create index if not exists ix_pending_password_reset_sessions_request
    on pending_password_reset_sessions(password_reset_request_id)
    where password_reset_request_id is not null;

create index if not exists ix_pending_password_reset_sessions_expiration
    on pending_password_reset_sessions(expires_at)
    where revoked_at is null;

create table if not exists password_reset_rate_limits(
    rate_limit_key text primary key,
    window_started_at timestamp with time zone not null,
    request_count integer not null default 0,
    last_request_at timestamp with time zone null,
    blocked_until timestamp with time zone null,
    constraint ck_password_reset_rate_limit_key_not_blank check (length(btrim(rate_limit_key)) > 0),
    constraint ck_password_reset_rate_limit_request_count_nonnegative check (request_count >= 0),
    constraint ck_password_reset_rate_limit_last_request_after_window check (last_request_at is null or last_request_at >= window_started_at)
);

create index if not exists ix_password_reset_rate_limits_blocked_until
    on password_reset_rate_limits(blocked_until)
    where blocked_until is not null;

create index if not exists ix_password_reset_rate_limits_window_started
    on password_reset_rate_limits(window_started_at);

create table if not exists password_reset_events(
    password_reset_event_id bigint generated always as identity primary key,
    password_reset_request_id uuid null,
    account_id uuid null references accounts(account_id) on delete set null,
    event_type text not null,
    code text not null,
    created_at timestamp with time zone not null default now(),
    constraint ck_password_reset_events_event_type check (length(btrim(event_type)) > 0),
    constraint ck_password_reset_events_code check (length(btrim(code)) > 0)
);

create index if not exists ix_password_reset_events_account_time
    on password_reset_events(account_id, created_at desc);

create index if not exists ix_password_reset_events_request_time
    on password_reset_events(password_reset_request_id, created_at desc);


create table if not exists activations(
    activation_id bigint generated always as identity primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    created_on timestamp with time zone not null default now(),
    term interval not null,
    off_at timestamp with time zone not null,
    feature_set smallint not null,
    code text not null,
    status smallint not null,
    day_duration smallint not null default 0,
    duration_repeat smallint not null default 0,
    platform_backer smallint null,
    platform_text text null,
    delayed_start timestamp with time zone null
);

create unique index if not exists ux_activations_code
    on activations(code);

create table if not exists delete_standby(
    account_id uuid primary key references accounts(account_id) on delete cascade,
    pass_phrase_hash text null,
    delete_token_hash text not null unique,
    expiration timestamp with time zone not null,
    verified boolean not null default false,
    requested_count smallint not null default 0,
    last_requested_at timestamp with time zone null,
    next_request_allowed_at timestamp with time zone null,
    failed_finalize_attempts smallint not null default 0,
    finalize_locked_until timestamp with time zone null
);

create index if not exists ix_delete_standby_expiration
    on delete_standby(expiration);

create index if not exists ix_delete_standby_next_request_allowed_at
    on delete_standby(next_request_allowed_at);

create table if not exists account_delete_events(
    delete_event_id bigint generated always as identity primary key,
    account_id uuid null,
    event_type text not null,
    code text not null,
    created_at timestamp with time zone not null default now(),
    constraint ck_account_delete_events_event_type check (length(trim(event_type)) > 0),
    constraint ck_account_delete_events_code check (length(trim(code)) > 0)
);

create index if not exists ix_account_delete_events_account_time
    on account_delete_events(account_id, created_at desc);

create index if not exists ix_account_delete_events_type_time
    on account_delete_events(event_type, created_at desc);

create table if not exists session_logout_events(
    logout_event_id bigint generated always as identity primary key,
    account_id uuid null,
    access_token_hash text null,
    logout_scope text not null,
    reason text null,
    requested_at timestamp with time zone not null default now(),
    completed boolean not null default false,
    code text null
);

create index if not exists ix_session_logout_events_account_time
    on session_logout_events(account_id, requested_at desc);

create or replace function setup_account_email(
    p_accountId uuid,
    p_emailAddress text,
    p_webKey text,
    p_hashedPassword bytea,
    p_saltOne bytea,
    p_siv bytea,
    p_nonce bytea,
    p_country smallint,
    p_verifyKeyHash text,
    p_createdOn timestamp with time zone,
    p_verificationExpiration interval)
returns table(verification_index bigint, outcome smallint)
language plpgsql
as $$
declare
    v_verification_index bigint;
begin
    if exists (select 1 from accounts where account_id = p_accountId) then
        return query select null::bigint, 3000::smallint;
        return;
    end if;

    if exists (select 1 from accounts where web_key = p_webKey) then
        return query select null::bigint, 3500::smallint;
        return;
    end if;

    if exists (select 1 from accounts where lower(email_address) = lower(p_emailAddress)) then
        return query select null::bigint, 8040::smallint;
        return;
    end if;

    insert into accounts(
        account_id, email_address, username, hashed_password, created_on, web_key,
        verify_status, salt_one, siv, nonce, unlock_when, login_failures,
        features, two_factor_auth_method, country)
    values(
        p_accountId, p_emailAddress, null, p_hashedPassword, p_createdOn, p_webKey,
        0, p_saltOne, p_siv, p_nonce, null, 0,
        0, 0, p_country);

    insert into account_verifications(account_id, verify_key_hash, verify_status, sent_when, expiration)
    values(p_accountId, p_verifyKeyHash, 0, null, greatest(coalesce(p_verificationExpiration, interval '1 day'), interval '1 minute'))
    returning account_verifications.verification_index into v_verification_index;

    return query select v_verification_index, 8000::smallint;
end;
$$;

create or replace function setup_account_both(
    p_accountId uuid,
    p_username text,
    p_emailAddress text,
    p_webKey text,
    p_hashedPassword bytea,
    p_saltOne bytea,
    p_siv bytea,
    p_nonce bytea,
    p_country smallint,
    p_verifyKeyHash text,
    p_createdOn timestamp with time zone,
    p_verificationExpiration interval)
returns table(verification_index bigint, outcome smallint)
language plpgsql
as $$
declare
    v_verification_index bigint;
    v_email_exists boolean;
    v_username_exists boolean;
begin
    if exists (select 1 from accounts where account_id = p_accountId) then
        return query select null::bigint, 3000::smallint;
        return;
    end if;

    if exists (select 1 from accounts where web_key = p_webKey) then
        return query select null::bigint, 3500::smallint;
        return;
    end if;

    select exists(select 1 from accounts where lower(email_address) = lower(p_emailAddress)) into v_email_exists;
    select exists(select 1 from accounts where lower(username) = lower(p_username)) into v_username_exists;

    if v_email_exists and v_username_exists then
        return query select null::bigint, 8070::smallint;
        return;
    end if;

    if v_email_exists then
        return query select null::bigint, 8040::smallint;
        return;
    end if;

    if v_username_exists then
        return query select null::bigint, 8010::smallint;
        return;
    end if;

    insert into accounts(
        account_id, email_address, username, hashed_password, created_on, web_key,
        verify_status, salt_one, siv, nonce, unlock_when, login_failures,
        features, two_factor_auth_method, country)
    values(
        p_accountId, p_emailAddress, p_username, p_hashedPassword, p_createdOn, p_webKey,
        0, p_saltOne, p_siv, p_nonce, null, 0,
        0, 0, p_country);

    insert into account_verifications(account_id, verify_key_hash, verify_status, sent_when, expiration)
    values(p_accountId, p_verifyKeyHash, 0, null, greatest(coalesce(p_verificationExpiration, interval '1 day'), interval '1 minute'))
    returning account_verifications.verification_index into v_verification_index;

    return query select v_verification_index, 8000::smallint;
end;
$$;

create or replace function start_verify_account(
    p_accountGuid uuid,
    p_verificationIndex bigint)
returns table(result boolean)
language plpgsql
as $$
begin
    update account_verifications
       set verify_status = 2,
           sent_when = now()
     where account_id = p_accountGuid
       and verification_index = p_verificationIndex
       and verify_status in (0, 4);

    if not found then
        return query select false;
        return;
    end if;

    update accounts
       set verify_status = 2
     where account_id = p_accountGuid;

    return query select true;
end;
$$;

create or replace function resend_verify_account(
    p_emailAddress text,
    p_verifyKeyHash text,
    p_verificationExpiration interval)
returns table(result boolean, code text, email_address text)
language plpgsql
as $$
declare
    v_account_id uuid;
    v_email_address text;
begin
    select a.account_id, a.email_address
      into v_account_id, v_email_address
      from accounts a
     where lower(a.email_address) = lower(p_emailAddress)
     limit 1;

    if not found then
        return query select true, 'VERIFICATION_RESEND_NOT_APPLICABLE', null::text;
        return;
    end if;

    if exists (
        select 1
          from accounts a
         where a.account_id = v_account_id
           and a.verify_status = 1) then
        return query select true, 'VERIFICATION_ALREADY_COMPLETE', null::text;
        return;
    end if;

    update account_verifications
       set verify_status = 3
     where account_id = v_account_id
       and verify_status <> 1;

    insert into account_verifications(account_id, verify_key_hash, verify_status, sent_when, expiration)
    values(v_account_id, p_verifyKeyHash, 4, now(), greatest(coalesce(p_verificationExpiration, interval '1 day'), interval '1 minute'));

    update accounts
       set verify_status = 4
     where account_id = v_account_id
       and verify_status <> 1;

    return query select true, 'VERIFICATION_RESEND_STARTED', v_email_address;
end;
$$;

create or replace function verify_account_for_use(p_verifyKeyHash text)
returns table(
    account_id uuid,
    verify_key_hash text,
    verify_status smallint,
    sent_when timestamp with time zone,
    expiration interval)
language sql
stable
as $$
    select av.account_id,
           av.verify_key_hash,
           av.verify_status,
           av.sent_when,
           av.expiration
      from account_verifications av
     where av.verify_key_hash = p_verifyKeyHash
     limit 1;
$$;

create or replace function complete_verify_account(
    p_accountId uuid,
    p_verifyKeyHash text)
returns table(result boolean)
language plpgsql
as $$
begin
    update account_verifications
       set verify_status = 1,
           sent_when = null,
           expiration = null
     where account_id = p_accountId
       and verify_key_hash = p_verifyKeyHash
       and verify_status in (2, 4);

    if not found then
        return query select false;
        return;
    end if;

    update accounts
       set verify_status = 1,
           login_failures = 0
     where account_id = p_accountId;

    return query select true;
end;
$$;

create or replace function expire_verify_account(
    p_accountId uuid,
    p_verifyKeyHash text)
returns table(result boolean)
language plpgsql
as $$
begin
    update account_verifications
       set verify_status = 3
     where account_id = p_accountId
       and verify_key_hash = p_verifyKeyHash
       and verify_status <> 1;

    if not found then
        return query select false;
        return;
    end if;

    update accounts
       set verify_status = 3
     where account_id = p_accountId
       and verify_status <> 1;

    return query select true;
end;
$$;

create or replace function get_session(p_accessTokenHash text)
returns table(
    account_id uuid,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    session_lifespan interval,
    access_expiration timestamp with time zone,
    session_expiration timestamp with time zone,
    cut_off timestamp with time zone,
    features smallint,
    security_stamp uuid,
    account_security_stamp uuid)
language sql
stable
as $$
    select s.account_id,
           s.refresh_token,
           s.refreshes,
           s.refresh_limit,
           s.created_on,
           s.session_lifespan,
           s.access_expiration,
           s.session_expiration,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           coalesce(s.features, 0)::smallint,
           s.security_stamp,
           s.account_security_stamp
      from sessions s
      join accounts a on a.account_id = s.account_id
     where s.access_token_hash = p_accessTokenHash
       and s.account_security_stamp = a.security_stamp
     limit 1;
$$;

create or replace function get_current_active_session_hash(
    p_accountId uuid)
returns table(active_access_token_hash text)
language sql
stable
as $$
    select s.access_token_hash
      from sessions s
      join accounts a on a.account_id = s.account_id
     where s.account_id = p_accountId
       and s.account_security_stamp = a.security_stamp
       and s.session_expiration > now()
     order by s.created_on desc nulls last,
              s.session_expiration desc,
              s.access_token_hash desc
     limit 1;
$$;

create or replace function check_account_emailaddress_creds(p_emailAddress text)
returns table(
    account_id uuid,
    hashed_password bytea,
    web_key text,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    lifespan interval,
    salt_one bytea,
    siv bytea,
    nonce bytea,
    unlock_when timestamp with time zone,
    login_failures smallint,
    verify_status smallint,
    features smallint,
    two_factor_access_token text,
    two_factor_auth_method smallint,
    two_auth_usage smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid,
    active_access_token_hash text)
language sql
stable
as $$
    select a.account_id,
           a.hashed_password,
           a.web_key,
           s.refresh_token,
           coalesce(s.refreshes, 0)::smallint,
           coalesce(s.refresh_limit, 0)::smallint,
           coalesce(s.created_on, now()),
           s.session_lifespan,
           a.salt_one,
           a.siv,
           a.nonce,
           a.unlock_when,
           coalesce(a.login_failures, 0)::smallint,
           coalesce(a.verify_status, 0)::smallint,
           coalesce(a.features, 0)::smallint,
           a.two_factor_access_token,
           coalesce(a.two_factor_auth_method, 0)::smallint,
           coalesce(a.two_auth_usage, 0)::smallint,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           a.security_stamp,
           s.access_token_hash
      from accounts a
      left join lateral (
            select sessions.access_token_hash,
                   sessions.refresh_token,
                   sessions.refreshes,
                   sessions.refresh_limit,
                   sessions.created_on,
                   sessions.session_lifespan,
                   sessions.session_expiration,
                   sessions.cut_off,
                   sessions.features
              from sessions
             where sessions.account_id = a.account_id
               and sessions.account_security_stamp = a.security_stamp
               and sessions.session_expiration > now()
             order by sessions.created_on desc nulls last,
                      sessions.session_expiration desc,
                      sessions.access_token_hash desc
             limit 1
      ) s on true
     where lower(a.email_address) = lower(p_emailAddress)
     limit 1;
$$;

create or replace function check_account_username_creds(p_username text)
returns table(
    account_id uuid,
    hashed_password bytea,
    web_key text,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    lifespan interval,
    salt_one bytea,
    siv bytea,
    nonce bytea,
    unlock_when timestamp with time zone,
    login_failures smallint,
    verify_status smallint,
    features smallint,
    two_factor_access_token text,
    two_factor_auth_method smallint,
    two_auth_usage smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid,
    active_access_token_hash text)
language sql
stable
as $$
    select a.account_id,
           a.hashed_password,
           a.web_key,
           s.refresh_token,
           coalesce(s.refreshes, 0)::smallint,
           coalesce(s.refresh_limit, 0)::smallint,
           coalesce(s.created_on, now()),
           s.session_lifespan,
           a.salt_one,
           a.siv,
           a.nonce,
           a.unlock_when,
           coalesce(a.login_failures, 0)::smallint,
           coalesce(a.verify_status, 0)::smallint,
           coalesce(a.features, 0)::smallint,
           a.two_factor_access_token,
           coalesce(a.two_factor_auth_method, 0)::smallint,
           coalesce(a.two_auth_usage, 0)::smallint,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           a.security_stamp,
           s.access_token_hash
      from accounts a
      left join lateral (
            select sessions.access_token_hash,
                   sessions.refresh_token,
                   sessions.refreshes,
                   sessions.refresh_limit,
                   sessions.created_on,
                   sessions.session_lifespan,
                   sessions.session_expiration,
                   sessions.cut_off,
                   sessions.features
              from sessions
             where sessions.account_id = a.account_id
               and sessions.account_security_stamp = a.security_stamp
               and sessions.session_expiration > now()
             order by sessions.created_on desc nulls last,
                      sessions.session_expiration desc,
                      sessions.access_token_hash desc
             limit 1
      ) s on true
     where lower(a.username) = lower(p_username)
     limit 1;
$$;

create or replace function check_account_both_creds(p_username text, p_emailAddress text)
returns table(
    account_id uuid,
    hashed_password bytea,
    web_key text,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    lifespan interval,
    salt_one bytea,
    siv bytea,
    nonce bytea,
    unlock_when timestamp with time zone,
    login_failures smallint,
    verify_status smallint,
    features smallint,
    two_factor_access_token text,
    two_factor_auth_method smallint,
    two_auth_usage smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid,
    active_access_token_hash text)
language sql
stable
as $$
    select a.account_id,
           a.hashed_password,
           a.web_key,
           s.refresh_token,
           coalesce(s.refreshes, 0)::smallint,
           coalesce(s.refresh_limit, 0)::smallint,
           coalesce(s.created_on, now()),
           s.session_lifespan,
           a.salt_one,
           a.siv,
           a.nonce,
           a.unlock_when,
           coalesce(a.login_failures, 0)::smallint,
           coalesce(a.verify_status, 0)::smallint,
           coalesce(a.features, 0)::smallint,
           a.two_factor_access_token,
           coalesce(a.two_factor_auth_method, 0)::smallint,
           coalesce(a.two_auth_usage, 0)::smallint,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           a.security_stamp,
           s.access_token_hash
      from accounts a
      left join lateral (
            select sessions.access_token_hash,
                   sessions.refresh_token,
                   sessions.refreshes,
                   sessions.refresh_limit,
                   sessions.created_on,
                   sessions.session_lifespan,
                   sessions.session_expiration,
                   sessions.cut_off,
                   sessions.features
              from sessions
             where sessions.account_id = a.account_id
               and sessions.account_security_stamp = a.security_stamp
               and sessions.session_expiration > now()
             order by sessions.created_on desc nulls last,
                      sessions.session_expiration desc,
                      sessions.access_token_hash desc
             limit 1
      ) s on true
     where lower(a.username) = lower(p_username)
       and lower(a.email_address) = lower(p_emailAddress)
     limit 1;
$$;


create or replace function get_account_reauthentication_credentials(
    p_accountId uuid,
    p_accountSecurityStamp uuid)
returns table(
    result boolean,
    code text,
    hashed_password bytea,
    verify_status smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid)
language sql
stable
as $$
    select true,
           'FOUND'::text,
           a.hashed_password,
           a.verify_status,
           a.cut_off,
           a.security_stamp
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     limit 1;
$$;

create or replace function issue_sensitive_action_token(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_sessionBindingHash text,
    p_tokenHash text,
    p_purpose smallint,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_consumeExistingTokens boolean)
returns table(result boolean, code text, token_id uuid, expiration timestamp with time zone)
language plpgsql
as $$
declare
    insertedTokenId uuid;
    accountVerified smallint;
    accountCutOff timestamp with time zone;
begin
    if p_purpose is null or p_purpose <= 0 then
        return query select false, 'INVALID_PURPOSE'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if p_sessionBindingHash is null or btrim(p_sessionBindingHash) = '' or p_tokenHash is null or btrim(p_tokenHash) = '' then
        return query select false, 'INVALID_TOKEN_REQUEST'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if p_expiration <= p_createdOn or p_expiration <= now() then
        return query select false, 'TOKEN_EXPIRATION_INVALID'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    select a.verify_status, a.cut_off
      into accountVerified, accountCutOff
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if accountVerified <> 1 then
        return query select false, 'ACCOUNT_NOT_VERIFIED'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if accountCutOff is not null and accountCutOff <= now() then
        return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if coalesce(p_consumeExistingTokens, true) then
        update account_sensitive_action_tokens sat
           set consumed_on = coalesce(sat.consumed_on, p_createdOn)
         where sat.account_id = p_accountId
           and sat.session_binding_hash = p_sessionBindingHash
           and sat.purpose = p_purpose
           and sat.consumed_on is null
           and sat.expiration > p_createdOn;
    end if;

    insert into account_sensitive_action_tokens(
        account_id,
        session_binding_hash,
        token_hash,
        purpose,
        created_on,
        expiration,
        account_security_stamp)
    values(
        p_accountId,
        p_sessionBindingHash,
        p_tokenHash,
        p_purpose,
        p_createdOn,
        p_expiration,
        p_accountSecurityStamp)
    returning account_sensitive_action_tokens.token_id
    into insertedTokenId;

    return query select true, 'SENSITIVE_ACTION_TOKEN_ISSUED'::text, insertedTokenId, p_expiration;
exception
    when unique_violation then
        return query select false, 'SENSITIVE_ACTION_TOKEN_CONFLICT'::text, null::uuid, null::timestamp with time zone;
    when others then
        raise;
end;
$$;

create or replace function validate_sensitive_action_token(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_sessionBindingHash text,
    p_tokenHash text,
    p_purpose smallint,
    p_consume boolean,
    p_moment timestamp with time zone)
returns table(result boolean, code text, expiration timestamp with time zone)
language plpgsql
as $$
declare
    tokenRecord account_sensitive_action_tokens%rowtype;
begin
    select *
      into tokenRecord
      from account_sensitive_action_tokens t
     where t.token_hash = p_tokenHash
     for update;

    if not found then
        return query select false, 'SENSITIVE_ACTION_TOKEN_INVALID'::text, null::timestamp with time zone;
        return;
    end if;

    if tokenRecord.account_id <> p_accountId
       or tokenRecord.account_security_stamp <> p_accountSecurityStamp
       or tokenRecord.session_binding_hash <> p_sessionBindingHash
       or tokenRecord.purpose <> p_purpose then
        return query select false, 'SENSITIVE_ACTION_TOKEN_INVALID'::text, tokenRecord.expiration;
        return;
    end if;

    if tokenRecord.consumed_on is not null then
        return query select false, 'SENSITIVE_ACTION_TOKEN_CONSUMED'::text, tokenRecord.expiration;
        return;
    end if;

    if tokenRecord.expiration <= p_moment then
        return query select false, 'SENSITIVE_ACTION_TOKEN_EXPIRED'::text, tokenRecord.expiration;
        return;
    end if;

    if coalesce(p_consume, false) then
        update account_sensitive_action_tokens
           set consumed_on = p_moment
         where token_id = tokenRecord.token_id;
    end if;

    return query select true, 'SENSITIVE_ACTION_TOKEN_VALID'::text, tokenRecord.expiration;
end;
$$;

create or replace function set_session(
    p_accessTokenHash text,
    p_accountId uuid,
    p_refreshToken bytea,
    p_refreshes smallint,
    p_refreshLimit smallint,
    p_createdOn timestamp with time zone,
    p_sessionLifespan interval,
    p_accessExpiration timestamp with time zone,
    p_sessionExpiration timestamp with time zone,
    p_cutOff timestamp with time zone,
    p_features smallint,
    p_securityStamp uuid,
    p_accountSecurityStamp uuid)
returns table(result smallint, code text)
language plpgsql
as $$
declare
    currentAccountCutOff timestamp with time zone;
    effectiveNewCutOff timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_accessTokenHash) then
        return query select 5000::smallint, 'NEW_SESSION_CONFLICT'::text; -- IntraMessage.AUTHENTICATION_DUPLICATE
        return;
    end if;

    -- A direct successful login mints a new active session. Lock the account row
    -- before expiring/inserting session rows so concurrent logins for an account
    -- serialize and cannot leave multiple active sessions behind.
    select a.cut_off
      into currentAccountCutOff
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select 5000::smallint, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    if currentAccountCutOff is not null and currentAccountCutOff <= now() then
        return query select 5000::smallint, 'ACCOUNT_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= now() then
        return query select 5000::smallint, 'SESSION_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and session_expiration > now();

    insert into sessions(
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_accessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        p_createdOn,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        p_features,
        p_securityStamp,
        p_accountSecurityStamp);

    return query select 1::smallint, 'SUCCESSFUL'::text; -- IntraMessage.SUCCESSFUL
exception
    when unique_violation then
        return query select 5000::smallint, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;

create or replace function update_refresh_token(p_accountId uuid, p_refreshToken bytea)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    targetHash text;
begin
    select s.access_token_hash
      into targetHash
      from sessions s
     where s.account_id = p_accountId
       and s.session_expiration > now()
     order by s.created_on desc nulls last,
              s.session_expiration desc,
              s.access_token_hash desc
     limit 1;

    if targetHash is null then
        return query select false, 'NO_ACTIVE_SESSION'::text;
        return;
    end if;

    update sessions
       set refresh_token = p_refreshToken
     where access_token_hash = targetHash;

    return query select found, case when found then 'UPDATED' else 'NO_ACTIVE_SESSION' end::text;
end;
$$;

create or replace function set_account_lockout(p_accountGuid uuid, p_expiration interval)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set unlock_when = now() + p_expiration
     where account_id = p_accountGuid;

    return query select found, case when found then 'LOCKED' else 'ACCOUNT_NOT_FOUND' end::text;
end;
$$;

create or replace function remove_account_lockout(p_accountGuid uuid)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set unlock_when = null,
           login_failures = 0
     where account_id = p_accountGuid;

    return query select found, case when found then 'UNLOCKED' else 'ACCOUNT_NOT_FOUND' end::text;
end;
$$;

create or replace function set_account_login_failures(p_accountGuid uuid, p_failures smallint)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set login_failures = p_failures
     where account_id = p_accountGuid;

    return query select found, case when found then 'UPDATED' else 'ACCOUNT_NOT_FOUND' end::text;
end;
$$;

create or replace function successful_login(
    p_accountId uuid,
    p_accountSecurityStamp uuid)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set login_failures = 0
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    return query select found, case when found then 'UPDATED' else 'ACCOUNT_STAMP_MISMATCH' end::text;
end;
$$;


create or replace function rotate_account_security_stamp(p_accountId uuid)
returns table(result boolean, code text, account_security_stamp uuid)
language plpgsql
as $$
declare
    rotatedAccountSecurityStamp uuid;
begin
    update accounts
       set security_stamp = gen_random_uuid(),
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
     returning security_stamp into rotatedAccountSecurityStamp;

    if rotatedAccountSecurityStamp is null then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::uuid;
        return;
    end if;

    -- DB-backed sessions are expired immediately. Any Redis entries that still
    -- exist will also fail trust validation because their account stamp is stale.
    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and session_expiration > now();

    delete from pending_two_factor_sessions
     where account_id = p_accountId;

    return query select true, 'ROTATED'::text, rotatedAccountSecurityStamp;
end;
$$;

create or replace function set_twofactor_auth_detail(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_twoFactorAccessToken text,
    p_twoAuthUsage smallint)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set two_factor_access_token = p_twoFactorAccessToken,
           two_auth_usage = p_twoAuthUsage
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    return query select found, case when found then 'UPDATED' else 'ACCOUNT_STAMP_MISMATCH' end::text;
end;
$$;

create or replace function begin_twofactor_auth_detail(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_twoFactorAccessToken text,
    p_twoAuthUsage smallint,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    resolved_available_configurations smallint[];
begin
    update accounts
       set two_factor_access_token = p_twoFactorAccessToken,
           two_auth_usage = p_twoAuthUsage
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    if not found then
        return query select false, 'ACCOUNT_STAMP_MISMATCH'::text;
        return;
    end if;

    resolved_available_configurations := resolve_available_twofactor_configurations(p_accountId);

    delete from pending_two_factor_sessions
     where account_id = p_accountId
       and pre_auth_access_token_hash <> p_twoFactorAccessToken;

    insert into pending_two_factor_sessions(
        pre_auth_access_token_hash,
        account_id,
        account_security_stamp,
        two_auth_usage,
        created_on,
        expiration,
        selected_two_factor_configuration,
        state,
        available_configurations,
        required_methods,
        completed_methods,
        current_expected_method,
        selected_at,
        completed_at)
    values(
        p_twoFactorAccessToken,
        p_accountId,
        p_accountSecurityStamp,
        p_twoAuthUsage,
        coalesce(p_createdOn, now()),
        p_expiration,
        null,
        1,
        resolved_available_configurations,
        array[]::smallint[],
        array[]::smallint[],
        null,
        null,
        null)
    on conflict(pre_auth_access_token_hash) do update
       set account_id = excluded.account_id,
           account_security_stamp = excluded.account_security_stamp,
           two_auth_usage = excluded.two_auth_usage,
           created_on = excluded.created_on,
           expiration = excluded.expiration,
           selected_two_factor_configuration = null,
           state = 1,
           available_configurations = resolved_available_configurations,
           required_methods = array[]::smallint[],
           completed_methods = array[]::smallint[],
           current_expected_method = null,
           selected_at = null,
           completed_at = null,
           challenged_method = null,
           chosen_destination = null,
           challenge_code_hash = null,
           challenge_provider_transaction_id = null,
           challenge_expiration = null,
           challenge_attempts = 0,
           challenge_resends = 0,
           next_challenge_allowed_at = null;

    return query select true, 'PENDING_TWO_FACTOR_SET'::text;
end;
$$;

create or replace function is_pending_twofactor_session_current(
    p_accountId uuid,
    p_expectedTwoFactorAccessToken text,
    p_accountSecurityStamp uuid)
returns table(result boolean, code text)
language sql
stable
as $$
    select exists(
        select 1
          from accounts a
          join pending_two_factor_sessions p
            on p.account_id = a.account_id
           and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
           and p.account_security_stamp = p_accountSecurityStamp
         where a.account_id = p_accountId
           and a.security_stamp = p_accountSecurityStamp
           and a.two_factor_access_token = p_expectedTwoFactorAccessToken
           and p.expiration > now()
    ) as result,
    case when exists(
        select 1
          from accounts a
          join pending_two_factor_sessions p
            on p.account_id = a.account_id
           and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
           and p.account_security_stamp = p_accountSecurityStamp
         where a.account_id = p_accountId
           and a.security_stamp = p_accountSecurityStamp
           and a.two_factor_access_token = p_expectedTwoFactorAccessToken
           and p.expiration > now()
    ) then 'CURRENT' else 'MISMATCH' end::text as code;
$$;

create or replace function record_twofactor_challenge_issued(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_expectedTwoFactorAccessToken text,
    p_challengedMethod smallint,
    p_chosenDestination smallint,
    p_challengeCodeHash text,
    p_challengeProviderTransactionId text,
    p_challengeExpiration timestamp with time zone,
    p_nextChallengeAllowedAt timestamp with time zone,
    p_maxResends smallint,
    p_now timestamp with time zone default now(),
    p_selectedTwoFactorConfiguration smallint default null,
    p_state smallint default null,
    p_requiredMethods smallint[] default null,
    p_completedMethods smallint[] default null,
    p_currentExpectedMethod smallint default null,
    p_selectedAt timestamp with time zone default null)
returns table(
    result boolean,
    code text,
    challenge_attempts smallint,
    challenge_resends smallint,
    challenge_expiration timestamp with time zone,
    next_challenge_allowed_at timestamp with time zone)
language plpgsql
as $$
declare
    pending pending_two_factor_sessions%rowtype;
    resolvedChallengeExpiration timestamp with time zone;
    resolvedSelectedConfiguration smallint;
    resolvedState smallint;
    resolvedRequiredMethods smallint[];
    resolvedCompletedMethods smallint[];
    resolvedCurrentExpectedMethod smallint;
    resolvedSelectedAt timestamp with time zone;
begin
    select p.*
      into pending
      from pending_two_factor_sessions p
      join accounts a on a.account_id = p.account_id
     where p.account_id = p_accountId
       and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
       and p.account_security_stamp = p_accountSecurityStamp
       and a.security_stamp = p_accountSecurityStamp
       and a.two_factor_access_token = p_expectedTwoFactorAccessToken
     for update;

    if not found then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text, 0::smallint, 0::smallint, null::timestamp with time zone, null::timestamp with time zone;
        return;
    end if;

    if pending.expiration <= p_now then
        return query select false, 'PENDING_TWO_FACTOR_EXPIRED'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
        return;
    end if;

    -- SMS and email challenges are delivered codes and must respect resend cooldowns.
    -- Authenticator-app proofs are generated locally from the enrolled TOTP secret, so
    -- advancing a combo flow from SMS/email to AUTHENTICATOR_APP must not be blocked by
    -- the prior delivered-code cooldown window.
    if p_challengedMethod <> 3 and pending.next_challenge_allowed_at is not null and pending.next_challenge_allowed_at > p_now then
        return query select false, 'TWO_FACTOR_CHALLENGE_COOLDOWN'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
        return;
    end if;

    if p_challengedMethod <> 3 and pending.challenge_resends >= p_maxResends then
        update accounts
           set two_factor_access_token = null,
               two_auth_usage = null
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp
           and two_factor_access_token = p_expectedTwoFactorAccessToken;

        delete from pending_two_factor_sessions
         where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

        return query select false, 'TWO_FACTOR_CHALLENGE_RESEND_LIMIT'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
        return;
    end if;

    resolvedChallengeExpiration := least(p_challengeExpiration, pending.expiration);
    resolvedSelectedConfiguration := coalesce(
        p_selectedTwoFactorConfiguration,
        pending.selected_two_factor_configuration,
        case p_challengedMethod
            when 1 then 2::smallint
            when 2 then 1::smallint
            when 3 then 3::smallint
            else null::smallint
        end);
    resolvedState := coalesce(
        p_state,
        case p_challengedMethod
            when 1 then 3::smallint
            when 2 then 2::smallint
            when 3 then 4::smallint
            else pending.state
        end);
    resolvedRequiredMethods := coalesce(
        p_requiredMethods,
        nullif(pending.required_methods, array[]::smallint[]),
        case when p_challengedMethod in (1, 2, 3) then array[p_challengedMethod]::smallint[] else array[]::smallint[] end);
    resolvedCompletedMethods := coalesce(p_completedMethods, pending.completed_methods, array[]::smallint[]);
    resolvedCurrentExpectedMethod := coalesce(p_currentExpectedMethod, pending.current_expected_method, p_challengedMethod);
    resolvedSelectedAt := coalesce(pending.selected_at, p_selectedAt, p_now);

    update pending_two_factor_sessions ptfs
       set selected_two_factor_configuration = resolvedSelectedConfiguration,
           state = resolvedState,
           required_methods = resolvedRequiredMethods,
           completed_methods = resolvedCompletedMethods,
           current_expected_method = resolvedCurrentExpectedMethod,
           selected_at = resolvedSelectedAt,
           completed_at = null,
           challenged_method = p_challengedMethod,
           chosen_destination = p_chosenDestination,
           challenge_code_hash = p_challengeCodeHash,
           challenge_provider_transaction_id = p_challengeProviderTransactionId,
           challenge_expiration = resolvedChallengeExpiration,
           challenge_attempts = 0,
           challenge_resends = case when p_challengedMethod = 3 then ptfs.challenge_resends else ptfs.challenge_resends + 1 end,
           next_challenge_allowed_at = case when p_challengedMethod = 3 then ptfs.next_challenge_allowed_at else p_nextChallengeAllowedAt end
     where ptfs.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
     returning ptfs.challenge_attempts,
               ptfs.challenge_resends,
               ptfs.challenge_expiration,
               ptfs.next_challenge_allowed_at
      into pending.challenge_attempts,
           pending.challenge_resends,
           pending.challenge_expiration,
           pending.next_challenge_allowed_at;

    return query select true, 'TWO_FACTOR_CHALLENGE_ISSUED'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
end;
$$;

create or replace function cancel_twofactor_challenge_issued(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_expectedTwoFactorAccessToken text,
    p_challengedMethod smallint,
    p_chosenDestination smallint,
    p_challengeCodeHash text,
    p_challengeProviderTransactionId text,
    p_now timestamp with time zone default now())
returns table(
    result boolean,
    code text,
    challenge_attempts smallint,
    challenge_resends smallint,
    challenge_expiration timestamp with time zone,
    next_challenge_allowed_at timestamp with time zone)
language plpgsql
as $$
declare
    pending pending_two_factor_sessions%rowtype;
    previousResends smallint;
begin
    select p.*
      into pending
      from pending_two_factor_sessions p
      join accounts a on a.account_id = p.account_id
     where p.account_id = p_accountId
       and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
       and p.account_security_stamp = p_accountSecurityStamp
       and a.security_stamp = p_accountSecurityStamp
       and a.two_factor_access_token = p_expectedTwoFactorAccessToken
     for update;

    if not found then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text, 0::smallint, 0::smallint, null::timestamp with time zone, null::timestamp with time zone;
        return;
    end if;

    if pending.expiration <= p_now then
        update accounts
           set two_factor_access_token = null,
               two_auth_usage = null
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp
           and two_factor_access_token = p_expectedTwoFactorAccessToken;

        delete from pending_two_factor_sessions
         where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

        return query select false, 'PENDING_TWO_FACTOR_EXPIRED'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
        return;
    end if;

    if pending.challenged_method is distinct from p_challengedMethod
       or pending.chosen_destination is distinct from p_chosenDestination
       or pending.challenge_code_hash is distinct from p_challengeCodeHash
       or pending.challenge_provider_transaction_id is distinct from p_challengeProviderTransactionId then
        return query select false, 'TWO_FACTOR_CHALLENGE_MISMATCH'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
        return;
    end if;

    previousResends := greatest((pending.challenge_resends - 1), 0)::smallint;

    update pending_two_factor_sessions
       set challenged_method = null,
           chosen_destination = null,
           challenge_code_hash = null,
           challenge_provider_transaction_id = null,
           challenge_expiration = null,
           challenge_attempts = 0,
           challenge_resends = previousResends,
           next_challenge_allowed_at = null
     where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
     returning pending_two_factor_sessions.challenge_attempts,
               pending_two_factor_sessions.challenge_resends,
               pending_two_factor_sessions.challenge_expiration,
               pending_two_factor_sessions.next_challenge_allowed_at
      into pending.challenge_attempts,
           pending.challenge_resends,
           pending.challenge_expiration,
           pending.next_challenge_allowed_at;

    return query select true, 'TWO_FACTOR_CHALLENGE_CANCELLED'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
end;
$$;

create or replace function record_twofactor_challenge_failure(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_expectedTwoFactorAccessToken text,
    p_maxAttempts smallint,
    p_now timestamp with time zone default now())
returns table(
    result boolean,
    code text,
    challenge_attempts smallint,
    challenge_resends smallint,
    challenge_expiration timestamp with time zone,
    next_challenge_allowed_at timestamp with time zone)
language plpgsql
as $$
declare
    pending pending_two_factor_sessions%rowtype;
    nextAttempts smallint;
begin
    select p.*
      into pending
      from pending_two_factor_sessions p
      join accounts a on a.account_id = p.account_id
     where p.account_id = p_accountId
       and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
       and p.account_security_stamp = p_accountSecurityStamp
       and a.security_stamp = p_accountSecurityStamp
       and a.two_factor_access_token = p_expectedTwoFactorAccessToken
     for update;

    if not found then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text, 0::smallint, 0::smallint, null::timestamp with time zone, null::timestamp with time zone;
        return;
    end if;

    if pending.expiration <= p_now or pending.challenge_expiration is null or pending.challenge_expiration <= p_now then
        update accounts
           set two_factor_access_token = null,
               two_auth_usage = null
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp
           and two_factor_access_token = p_expectedTwoFactorAccessToken;

        delete from pending_two_factor_sessions
         where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

        return query select false, 'PENDING_TWO_FACTOR_EXPIRED'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
        return;
    end if;

    nextAttempts := pending.challenge_attempts + 1;

    if nextAttempts >= p_maxAttempts then
        update accounts
           set two_factor_access_token = null,
               two_auth_usage = null
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp
           and two_factor_access_token = p_expectedTwoFactorAccessToken;

        delete from pending_two_factor_sessions
         where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

        return query select false, 'TWO_FACTOR_CHALLENGE_ATTEMPT_LIMIT'::text, nextAttempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
        return;
    end if;

    update pending_two_factor_sessions
       set challenge_attempts = nextAttempts
     where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
     returning pending_two_factor_sessions.challenge_attempts,
               pending_two_factor_sessions.challenge_resends,
               pending_two_factor_sessions.challenge_expiration,
               pending_two_factor_sessions.next_challenge_allowed_at
      into pending.challenge_attempts,
           pending.challenge_resends,
           pending.challenge_expiration,
           pending.next_challenge_allowed_at;

    return query select true, 'TWO_FACTOR_CHALLENGE_FAILURE_RECORDED'::text, pending.challenge_attempts, pending.challenge_resends, pending.challenge_expiration, pending.next_challenge_allowed_at;
end;
$$;

create or replace function successful_twofactor_auth(
    p_accountId uuid,
    p_expectedTwoFactorAccessToken text,
    p_accountSecurityStamp uuid)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set login_failures = 0,
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp
       and two_factor_access_token = p_expectedTwoFactorAccessToken;

    if found then
        delete from pending_two_factor_sessions
         where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;
    end if;

    return query select found, case when found then 'UPDATED' else 'PENDING_SESSION_MISMATCH' end::text;
end;
$$;

-- Account operation contract functions. Account operations must be driven by
-- authenticated account context rather than body-supplied ownership fields.
create or replace function edit_account_username(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_username text)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    normalized_username text := nullif(btrim(p_username), '');
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    if normalized_username is null or char_length(normalized_username) > 128 then
        return query select false, 'ACCOUNT_ADJUST_FAILED'::text;
        return;
    end if;

    if exists (
        select 1
          from accounts
         where account_id <> p_accountId
           and username is not null
           and lower(username) = lower(normalized_username)
    ) then
        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_USERNAME'::text;
        return;
    end if;

    update accounts
       set username = normalized_username
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    if found then
        return query select true, 'ACCOUNT_ADJUST_SUCCEEDED'::text;
    else
        return query select false, 'ACCOUNT_ADJUST_FAILED'::text;
    end if;
exception
    when unique_violation then
        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_USERNAME'::text;
end;
$$;

create or replace function request_account_email_change(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_newEmailAddress text,
    p_verifyKeyHash text,
    p_expiration timestamp with time zone)
returns table(result boolean, code text, email_address text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    normalized_email text := lower(nullif(btrim(p_newEmailAddress), ''));
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::text;
        return;
    end if;

    if normalized_email is null or char_length(normalized_email) > 1024 then
        return query select false, 'ACCOUNT_ADJUST_FAILED'::text, null::text;
        return;
    end if;

    if p_expiration is null or p_expiration <= now() then
        return query select false, 'ACCOUNT_ADJUST_FAILED'::text, null::text;
        return;
    end if;

    if exists (
        select 1
          from accounts a
         where lower(a.email_address) = normalized_email
    ) then
        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text, null::text;
        return;
    end if;

    if exists (
        select 1
          from account_email_change_requests ecr
         where ecr.account_id <> p_accountId
           and lower(ecr.new_email_address) = normalized_email
    ) then
        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text, null::text;
        return;
    end if;

    insert into account_email_change_requests(
        account_id,
        new_email_address,
        verify_key_hash,
        requested_at,
        expiration,
        account_security_stamp)
    values (
        p_accountId,
        normalized_email,
        p_verifyKeyHash,
        now(),
        p_expiration,
        p_accountSecurityStamp)
    on conflict (account_id) do update
       set new_email_address = excluded.new_email_address,
           verify_key_hash = excluded.verify_key_hash,
           requested_at = now(),
           expiration = excluded.expiration,
           account_security_stamp = excluded.account_security_stamp;

    return query select true, 'ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING'::text, normalized_email;
exception
    when unique_violation then
        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text, null::text;
end;
$$;

create or replace function cancel_account_email_change_request(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_verifyKeyHash text)
returns table(result boolean, code text, email_address text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    request_record account_email_change_requests%rowtype;
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::text;
        return;
    end if;

    select *
      into request_record
      from account_email_change_requests
     where account_id = p_accountId
       and account_security_stamp = p_accountSecurityStamp
       and verify_key_hash = p_verifyKeyHash
     for update;

    if not found then
        return query select false, 'ACCOUNT_ADJUST_TOKEN_MISMATCH'::text, null::text;
        return;
    end if;

    delete from account_email_change_requests
     where account_id = p_accountId
       and account_security_stamp = p_accountSecurityStamp
       and verify_key_hash = p_verifyKeyHash;

    return query select true, 'ACCOUNT_ADJUST_EMAIL_CHANGE_CANCELLED'::text, request_record.new_email_address;
exception
    when others then
        return query select false, 'ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED'::text, null::text;
end;
$$;

create or replace function complete_account_email_change(
    p_verifyKeyHash text)
returns table(result boolean, code text, account_security_stamp uuid)
language plpgsql
as $$
declare
    request_record account_email_change_requests%rowtype;
    new_security_stamp uuid := gen_random_uuid();
begin
    select *
      into request_record
      from account_email_change_requests
     where verify_key_hash = p_verifyKeyHash
     for update;

    if not found then
        return query select false, 'ACCOUNT_ADJUST_TOKEN_MISMATCH'::text, null::uuid;
        return;
    end if;

    if request_record.expiration <= now() then
        delete from account_email_change_requests
         where account_id = request_record.account_id;

        return query select false, 'ACCOUNT_ADJUST_TOKEN_EXPIRED'::text, null::uuid;
        return;
    end if;

    if exists (
        select 1
          from accounts
         where lower(email_address) = lower(request_record.new_email_address)
           and account_id <> request_record.account_id
    ) then
        delete from account_email_change_requests
         where account_id = request_record.account_id;

        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text, null::uuid;
        return;
    end if;

    update accounts
       set email_address = request_record.new_email_address,
           security_stamp = new_security_stamp
     where account_id = request_record.account_id
       and security_stamp = request_record.account_security_stamp;

    if not found then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid;
        return;
    end if;

    -- Email 2FA is bound to the account email. After an account email change,
    -- remove the verified email factor so it cannot silently follow a new destination.
    delete from two_factor_authentications
     where account_id = request_record.account_id
       and method = 1
       and verified = true;

    with remaining as (
        select t.method
          from two_factor_authentications t
         where t.account_id = request_record.account_id
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > now())
         order by t.required desc, t.priority desc, t.two_factor_index asc
    ), remaining_summary as (
        select coalesce((select method from remaining limit 1), 0)::smallint as selected_method,
               nullif((select count(*) from remaining), 0)::smallint as usage_count
    )
    update accounts a
       set two_factor_auth_method = remaining_summary.selected_method,
           two_auth_usage = remaining_summary.usage_count
      from remaining_summary
     where a.account_id = request_record.account_id;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now())),
           cut_off = now()
     where account_id = request_record.account_id;

    delete from account_email_change_requests
     where account_id = request_record.account_id;

    return query select true, 'ACCOUNT_ADJUST_SUCCEEDED'::text, new_security_stamp;
end;
$$;

create or replace function purge_expired_account_email_change_requests(
    p_now timestamp with time zone default now())
returns table(result boolean, code text, deleted_count integer)
language plpgsql
as $$
declare
    affected_rows integer;
begin
    delete from account_email_change_requests
     where expiration <= p_now;

    get diagnostics affected_rows = row_count;
    return query select true, 'ACCOUNT_ADJUST_PURGE_SUCCEEDED'::text, affected_rows;
exception
    when others then
        return query select false, 'ACCOUNT_ADJUST_PURGE_FAILED'::text, 0;
end;
$$;

create or replace function request_account_delete(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_passPhraseHash text,
    p_deleteTokenHash text,
    p_expiration timestamp with time zone,
    p_requestCooldown interval,
    p_requestWindow interval,
    p_maxRequestsPerWindow smallint)
returns table(result boolean, code text, email_address text, workflow smallint)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    existing_delete delete_standby%rowtype;
    requested_workflow smallint;
    next_requested_count smallint := 1;
begin
    if p_deleteTokenHash is null or length(trim(p_deleteTokenHash)) = 0 then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::text, 0::smallint;
        return;
    end if;

    if p_expiration is null or p_expiration <= now() then
        return query select false, 'ACCOUNT_DELETE_FAILED'::text, null::text, 0::smallint;
        return;
    end if;

    if p_requestCooldown is null or p_requestCooldown <= interval '0 seconds'
       or p_requestWindow is null or p_requestWindow <= interval '0 seconds'
       or p_maxRequestsPerWindow is null or p_maxRequestsPerWindow <= 0 then
        return query select false, 'ACCOUNT_DELETE_FAILED'::text, null::text, 0::smallint;
        return;
    end if;

    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::text, 0::smallint;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::text, 0::smallint;
        return;
    end if;

    select *
      into existing_delete
      from delete_standby
     where account_id = p_accountId
     for update;

    if found and existing_delete.expiration > now() then
        if existing_delete.next_request_allowed_at is not null
           and existing_delete.next_request_allowed_at > now() then
            insert into account_delete_events(account_id, event_type, code)
            values (p_accountId, 'REQUEST_RATE_LIMITED', 'ACCOUNT_DELETE_RATE_LIMITED');

            return query select false, 'ACCOUNT_DELETE_RATE_LIMITED'::text, null::text, 0::smallint;
            return;
        end if;

        if existing_delete.last_requested_at is not null
           and existing_delete.last_requested_at > now() - p_requestWindow then
            if existing_delete.requested_count >= p_maxRequestsPerWindow then
                insert into account_delete_events(account_id, event_type, code)
                values (p_accountId, 'REQUEST_RATE_LIMITED', 'ACCOUNT_DELETE_RATE_LIMITED');

                return query select false, 'ACCOUNT_DELETE_RATE_LIMITED'::text, null::text, 0::smallint;
                return;
            end if;

            next_requested_count := least((existing_delete.requested_count + 1)::integer, p_maxRequestsPerWindow::integer)::smallint;
        end if;
    end if;

    requested_workflow := case
        when p_passPhraseHash is null or length(trim(p_passPhraseHash)) = 0 then 1::smallint
        else 2::smallint
    end;

    insert into delete_standby(
        account_id,
        pass_phrase_hash,
        delete_token_hash,
        expiration,
        verified,
        requested_count,
        last_requested_at,
        next_request_allowed_at,
        failed_finalize_attempts,
        finalize_locked_until)
    values (
        p_accountId,
        nullif(trim(p_passPhraseHash), ''),
        p_deleteTokenHash,
        p_expiration,
        false,
        next_requested_count,
        now(),
        now() + p_requestCooldown,
        0,
        null)
    on conflict (account_id) do update
       set pass_phrase_hash = excluded.pass_phrase_hash,
           delete_token_hash = excluded.delete_token_hash,
           expiration = excluded.expiration,
           verified = false,
           requested_count = excluded.requested_count,
           last_requested_at = excluded.last_requested_at,
           next_request_allowed_at = excluded.next_request_allowed_at,
           failed_finalize_attempts = 0,
           finalize_locked_until = null;

    insert into account_delete_events(account_id, event_type, code)
    values (p_accountId, 'REQUESTED', 'ACCOUNT_DELETE_PENDING');

    return query select true, 'ACCOUNT_DELETE_PENDING'::text, account_record.email_address, requested_workflow;
exception
    when unique_violation then
        return query select false, 'ACCOUNT_DELETE_FAILED'::text, null::text, 0::smallint;
end;
$$;

create or replace function cancel_account_delete_request(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_deleteTokenHash text)
returns table(result boolean, code text, email_address text, workflow smallint)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    delete_record delete_standby%rowtype;
    resolved_workflow smallint;
begin
    if p_deleteTokenHash is null or length(trim(p_deleteTokenHash)) = 0 then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::text, 0::smallint;
        return;
    end if;

    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::text, 0::smallint;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::text, 0::smallint;
        return;
    end if;

    select d.*
      into delete_record
      from delete_standby d
     where d.account_id = p_accountId
       and d.delete_token_hash = p_deleteTokenHash
     for update;

    if not found then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::text, 0::smallint;
        return;
    end if;

    resolved_workflow := case
        when delete_record.pass_phrase_hash is null then 1::smallint
        else 2::smallint
    end;

    delete from delete_standby
     where account_id = p_accountId
       and delete_token_hash = p_deleteTokenHash;

    insert into account_delete_events(account_id, event_type, code)
    values (p_accountId, 'REQUEST_CANCELLED', 'ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED');

    return query select
        true,
        'ACCOUNT_DELETE_REQUEST_CANCELLED'::text,
        account_record.email_address,
        resolved_workflow;
exception
    when others then
        return query select false, 'ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED'::text, null::text, 0::smallint;
end;
$$;

create or replace function prepare_account_delete_finalize(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_deleteTokenHash text,
    p_maxFailedFinalizeAttempts smallint,
    p_finalizeLockout interval)
returns table(result boolean, code text, account_id uuid, workflow smallint, pass_phrase_hash text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    delete_record delete_standby%rowtype;
begin
    if p_deleteTokenHash is null or length(trim(p_deleteTokenHash)) = 0 then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    if p_maxFailedFinalizeAttempts is null or p_maxFailedFinalizeAttempts <= 0
       or p_finalizeLockout is null or p_finalizeLockout <= interval '0 seconds' then
        return query select false, 'ACCOUNT_DELETE_FAILED'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    select d.*
      into delete_record
      from delete_standby d
     where d.account_id = p_accountId
       and d.delete_token_hash = p_deleteTokenHash
     for update;

    if not found then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    if delete_record.finalize_locked_until is not null
       and delete_record.finalize_locked_until > now() then
        insert into account_delete_events(account_id, event_type, code)
        values (p_accountId, 'FINALIZE_LOCKED', 'ACCOUNT_DELETE_ATTEMPT_LIMITED');

        return query select false, 'ACCOUNT_DELETE_ATTEMPT_LIMITED'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    if delete_record.expiration <= now() then
        return query select false, 'ACCOUNT_DELETE_TOKEN_EXPIRED'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    if delete_record.verified is distinct from true then
        return query select false, 'ACCOUNT_DELETE_VERIFY_REQUIRED'::text, null::uuid, 0::smallint, null::text;
        return;
    end if;

    return query select
        true,
        'ACCOUNT_DELETE_VERIFIED'::text,
        p_accountId,
        case when delete_record.pass_phrase_hash is null then 1::smallint else 2::smallint end,
        delete_record.pass_phrase_hash;
end;
$$;

create or replace function commit_account_delete_finalize(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_deleteTokenHash text,
    p_passPhraseSatisfied boolean,
    p_maxFailedFinalizeAttempts smallint,
    p_finalizeLockout interval)
returns table(result boolean, code text, account_id uuid)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    delete_record delete_standby%rowtype;
    next_failed_attempts smallint;
begin
    if p_deleteTokenHash is null or length(trim(p_deleteTokenHash)) = 0 then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::uuid;
        return;
    end if;

    if p_maxFailedFinalizeAttempts is null or p_maxFailedFinalizeAttempts <= 0
       or p_finalizeLockout is null or p_finalizeLockout <= interval '0 seconds' then
        return query select false, 'ACCOUNT_DELETE_FAILED'::text, null::uuid;
        return;
    end if;

    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::uuid;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid;
        return;
    end if;

    select d.*
      into delete_record
      from delete_standby d
     where d.account_id = p_accountId
       and d.delete_token_hash = p_deleteTokenHash
     for update;

    if not found then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::uuid;
        return;
    end if;

    if delete_record.finalize_locked_until is not null
       and delete_record.finalize_locked_until > now() then
        insert into account_delete_events(account_id, event_type, code)
        values (p_accountId, 'FINALIZE_LOCKED', 'ACCOUNT_DELETE_ATTEMPT_LIMITED');

        return query select false, 'ACCOUNT_DELETE_ATTEMPT_LIMITED'::text, null::uuid;
        return;
    end if;

    if delete_record.expiration <= now() then
        return query select false, 'ACCOUNT_DELETE_TOKEN_EXPIRED'::text, null::uuid;
        return;
    end if;

    if delete_record.verified is distinct from true then
        return query select false, 'ACCOUNT_DELETE_VERIFY_REQUIRED'::text, null::uuid;
        return;
    end if;

    if delete_record.pass_phrase_hash is not null and p_passPhraseSatisfied is distinct from true then
        next_failed_attempts := least((delete_record.failed_finalize_attempts + 1)::integer, p_maxFailedFinalizeAttempts::integer)::smallint;

        update delete_standby d
           set failed_finalize_attempts = next_failed_attempts,
               finalize_locked_until = case
                   when next_failed_attempts >= p_maxFailedFinalizeAttempts then now() + p_finalizeLockout
                   else d.finalize_locked_until
               end
         where d.account_id = p_accountId;

        if next_failed_attempts >= p_maxFailedFinalizeAttempts then
            insert into account_delete_events(account_id, event_type, code)
            values (p_accountId, 'FINALIZE_LOCKED', 'ACCOUNT_DELETE_ATTEMPT_LIMITED');

            return query select false, 'ACCOUNT_DELETE_ATTEMPT_LIMITED'::text, null::uuid;
            return;
        end if;

        insert into account_delete_events(account_id, event_type, code)
        values (p_accountId, 'FINALIZE_FAILED', 'ACCOUNT_DELETE_TOKEN_MISMATCH');

        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, null::uuid;
        return;
    end if;

    insert into account_delete_events(account_id, event_type, code)
    values (p_accountId, 'COMPLETED', 'ACCOUNT_DELETE_SUCCEEDED');

    delete from accounts a
     where a.account_id = p_accountId;

    return query select true, 'ACCOUNT_DELETE_SUCCEEDED'::text, p_accountId;
end;
$$;

create or replace function rotate_active_session(
    p_accountId uuid,
    p_expectedOldAccessTokenHash text,
    p_newAccessTokenHash text,
    p_refreshToken bytea,
    p_refreshes smallint,
    p_refreshLimit smallint,
    p_createdOn timestamp with time zone,
    p_sessionLifespan interval,
    p_accessExpiration timestamp with time zone,
    p_sessionExpiration timestamp with time zone,
    p_cutOff timestamp with time zone,
    p_features smallint,
    p_securityStamp uuid,
    p_accountSecurityStamp uuid)
returns table(status smallint, code text)
language plpgsql
as $$
declare
    oldSessionLocked boolean := false;
    currentAccountCutOff timestamp with time zone;
    effectiveOldCutOff timestamp with time zone;
    effectiveNewCutOff timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then
        return query select 3::smallint, 'NEW_SESSION_CONFLICT'::text;
        return;
    end if;

    -- Lock the account before touching session rows so direct login, refresh
    -- rotation, and 2FA promotion all serialize on the same account-scoped
    -- session ownership boundary.
    select a.cut_off
      into currentAccountCutOff
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    select case
               when s.cut_off is null then currentAccountCutOff
               when currentAccountCutOff is null then s.cut_off
               else least(s.cut_off, currentAccountCutOff)
           end
      into effectiveOldCutOff
      from sessions s
     where s.account_id = p_accountId
       and s.access_token_hash = p_expectedOldAccessTokenHash
       and s.account_security_stamp = p_accountSecurityStamp
       and s.session_expiration > now()
     for update;

    oldSessionLocked := found;

    if not oldSessionLocked or (effectiveOldCutOff is not null and effectiveOldCutOff <= now()) then
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= now() then
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and access_token_hash <> p_expectedOldAccessTokenHash
       and session_expiration > now();

    insert into sessions(
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_newAccessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        p_createdOn,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        p_features,
        p_securityStamp,
        p_accountSecurityStamp);

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and access_token_hash = p_expectedOldAccessTokenHash
       and session_expiration > now();

    if not found then
        delete from sessions where access_token_hash = p_newAccessTokenHash;
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    update accounts
       set login_failures = 0
     where account_id = p_accountId;

    return query select 1::smallint, 'SUCCEEDED'::text;
exception
    when unique_violation then
        return query select 3::smallint, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;

create or replace function promote_twofactor_new_login(
    p_accountId uuid,
    p_expectedTwoFactorAccessToken text,
    p_accountSecurityStamp uuid,
    p_newAccessTokenHash text,
    p_refreshToken bytea,
    p_refreshes smallint,
    p_refreshLimit smallint,
    p_createdOn timestamp with time zone,
    p_sessionLifespan interval,
    p_accessExpiration timestamp with time zone,
    p_sessionExpiration timestamp with time zone,
    p_cutOff timestamp with time zone,
    p_features smallint,
    p_securityStamp uuid)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    currentAccountCutOff timestamp with time zone;
    currentPendingToken text;
    effectiveNewCutOff timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
        return;
    end if;

    select a.cut_off,
           a.two_factor_access_token
      into currentAccountCutOff,
           currentPendingToken
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    if currentPendingToken is distinct from p_expectedTwoFactorAccessToken then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    if not exists (
        select 1
          from pending_two_factor_sessions p
         where p.account_id = p_accountId
           and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
           and p.account_security_stamp = p_accountSecurityStamp
           and p.expiration > now()) then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    if currentAccountCutOff is not null and currentAccountCutOff <= now() then
        return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= now() then
        return query select false, 'SESSION_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and session_expiration > now();

    insert into sessions(
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_newAccessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        p_createdOn,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        coalesce(p_features, 0),
        p_securityStamp,
        p_accountSecurityStamp);

    update accounts
       set login_failures = 0,
           unlock_when = null,
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp
       and two_factor_access_token = p_expectedTwoFactorAccessToken;

    if not found then
        raise exception '2FA pending marker changed during promote_twofactor_new_login for account %', p_accountId;
    end if;

    delete from pending_two_factor_sessions
     where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

    return query select true, 'TWO_FACTOR_NEW_LOGIN_PROMOTED'::text;
exception
    when unique_violation then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;

create or replace function promote_twofactor_rotation_login(
    p_accountId uuid,
    p_expectedTwoFactorAccessToken text,
    p_accountSecurityStamp uuid,
    p_expectedOldAccessTokenHash text,
    p_newAccessTokenHash text,
    p_refreshToken bytea,
    p_refreshes smallint,
    p_refreshLimit smallint,
    p_createdOn timestamp with time zone,
    p_sessionLifespan interval,
    p_accessExpiration timestamp with time zone,
    p_sessionExpiration timestamp with time zone,
    p_cutOff timestamp with time zone,
    p_features smallint,
    p_securityStamp uuid)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    currentAccountCutOff timestamp with time zone;
    currentPendingToken text;
    oldSessionCutOff timestamp with time zone;
    oldSessionExpiration timestamp with time zone;
    effectiveOldCutOff timestamp with time zone;
    effectiveNewCutOff timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
        return;
    end if;

    select a.cut_off,
           a.two_factor_access_token
      into currentAccountCutOff,
           currentPendingToken
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    if currentPendingToken is distinct from p_expectedTwoFactorAccessToken then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    if not exists (
        select 1
          from pending_two_factor_sessions p
         where p.account_id = p_accountId
           and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
           and p.account_security_stamp = p_accountSecurityStamp
           and p.expiration > now()) then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    select s.cut_off,
           s.session_expiration
      into oldSessionCutOff,
           oldSessionExpiration
      from sessions s
     where s.account_id = p_accountId
       and s.access_token_hash = p_expectedOldAccessTokenHash
       and s.account_security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'OLD_SESSION_NOT_FOUND'::text;
        return;
    end if;

    effectiveOldCutOff := case
        when oldSessionCutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then oldSessionCutOff
        else least(oldSessionCutOff, currentAccountCutOff)
    end;

    if oldSessionExpiration <= now() or (effectiveOldCutOff is not null and effectiveOldCutOff <= now()) then
        return query select false, 'OLD_SESSION_EXPIRED'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= now() then
        return query select false, 'SESSION_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and access_token_hash <> p_expectedOldAccessTokenHash
       and session_expiration > now();

    insert into sessions(
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_newAccessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        p_createdOn,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        coalesce(p_features, 0),
        p_securityStamp,
        p_accountSecurityStamp);

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and access_token_hash = p_expectedOldAccessTokenHash
       and session_expiration > now();

    if not found then
        raise exception 'Old 2FA rotation session changed during promote_twofactor_rotation_login for account %', p_accountId;
    end if;

    update accounts
       set login_failures = 0,
           unlock_when = null,
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp
       and two_factor_access_token = p_expectedTwoFactorAccessToken;

    if not found then
        raise exception '2FA pending marker changed during promote_twofactor_rotation_login for account %', p_accountId;
    end if;

    delete from pending_two_factor_sessions
     where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

    return query select true, 'TWO_FACTOR_ROTATION_LOGIN_PROMOTED'::text;
exception
    when unique_violation then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;

create or replace function validate_cached_session_trust(
    p_accessTokenHash text,
    p_accountId uuid,
    p_securityStamp uuid,
    p_accountSecurityStamp uuid)
returns table(
    status smallint,
    code text,
    access_expiration timestamp with time zone,
    session_expiration timestamp with time zone,
    cut_off timestamp with time zone,
    security_stamp uuid,
    account_security_stamp uuid)
language plpgsql
stable
as $$
declare
    sessionRecord record;
    sessionFound boolean;
    currentAccountSecurityStamp uuid;
    currentAccountCutOff timestamp with time zone;
    effectiveCutOff timestamp with time zone;
begin
    select s.access_expiration,
           s.session_expiration,
           s.cut_off,
           s.security_stamp,
           s.account_security_stamp
      into sessionRecord
      from sessions s
     where s.access_token_hash = p_accessTokenHash
       and s.account_id = p_accountId
     limit 1;

    sessionFound := found;

    select a.security_stamp,
           a.cut_off
      into currentAccountSecurityStamp,
           currentAccountCutOff
      from accounts a
     where a.account_id = p_accountId
     limit 1;

    if currentAccountSecurityStamp is null then
        return query select 3::smallint, 'ACCOUNT_NOT_FOUND'::text, null::timestamp with time zone, null::timestamp with time zone, null::timestamp with time zone, null::uuid, null::uuid;
        return;
    end if;

    if not sessionFound then
        return query select 2::smallint, 'SESSION_NOT_FOUND'::text, null::timestamp with time zone, null::timestamp with time zone, null::timestamp with time zone, null::uuid, currentAccountSecurityStamp;
        return;
    end if;

    effectiveCutOff := case
        when sessionRecord.cut_off is null then currentAccountCutOff
        when currentAccountCutOff is null then sessionRecord.cut_off
        else least(sessionRecord.cut_off, currentAccountCutOff)
    end;

    if sessionRecord.security_stamp <> p_securityStamp then
        return query select 4::smallint, 'SECURITY_STAMP_MISMATCH'::text, sessionRecord.access_expiration, sessionRecord.session_expiration, effectiveCutOff, sessionRecord.security_stamp, currentAccountSecurityStamp;
        return;
    end if;

    if sessionRecord.account_security_stamp <> p_accountSecurityStamp
       or currentAccountSecurityStamp <> p_accountSecurityStamp then
        return query select 6::smallint, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, sessionRecord.access_expiration, sessionRecord.session_expiration, effectiveCutOff, sessionRecord.security_stamp, currentAccountSecurityStamp;
        return;
    end if;

    if sessionRecord.access_expiration <= now()
        or sessionRecord.session_expiration <= now()
        or (effectiveCutOff is not null and effectiveCutOff <= now()) then
        return query select 5::smallint, 'SESSION_EXPIRED'::text, sessionRecord.access_expiration, sessionRecord.session_expiration, effectiveCutOff, sessionRecord.security_stamp, currentAccountSecurityStamp;
        return;
    end if;

    return query select 1::smallint, 'VALID'::text, sessionRecord.access_expiration, sessionRecord.session_expiration, effectiveCutOff, sessionRecord.security_stamp, currentAccountSecurityStamp;
end;
$$;

create or replace function expire_session(p_accessTokenHash text, p_newExpiration timestamp with time zone)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    effectiveExpiration timestamp with time zone := coalesce(p_newExpiration, now());
begin
    update sessions
       set access_expiration = least(access_expiration, effectiveExpiration),
           session_expiration = least(session_expiration, effectiveExpiration)
     where access_token_hash = p_accessTokenHash;

    return query select found, case when found then 'EXPIRED' else 'SESSION_NOT_FOUND' end::text;
end;
$$;

create or replace function revoke_session(p_accessTokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    -- Legacy compatibility wrapper. Runtime repository code uses expire_session; hard deletion is reserved for cleanup jobs.
    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where access_token_hash = p_accessTokenHash;

    return query select found, case when found then 'EXPIRED' else 'SESSION_NOT_FOUND' end::text;
end;
$$;


create or replace function logout_current_session(
    p_accountId uuid,
    p_accessTokenHash text,
    p_accountSecurityStamp uuid,
    p_reason text default 'current-session-logoff')
returns table(result boolean, code text)
language plpgsql
as $$
begin
    if not exists (
        select 1
          from accounts a
         where a.account_id = p_accountId
           and a.security_stamp = p_accountSecurityStamp
    ) then
        insert into session_logout_events(
            account_id,
            access_token_hash,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            p_accessTokenHash,
            'current',
            p_reason,
            false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH');

        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    update sessions s
       set access_expiration = least(s.access_expiration, greatest(s.created_on, now())),
           session_expiration = least(s.session_expiration, greatest(s.created_on, now()))
     where s.access_token_hash = p_accessTokenHash
       and s.account_id = p_accountId
       and s.account_security_stamp = p_accountSecurityStamp
       and s.session_expiration > now();

    if not found then
        insert into session_logout_events(
            account_id,
            access_token_hash,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            p_accessTokenHash,
            'current',
            p_reason,
            true,
            'SESSION_ALREADY_MISSING_OR_STALE');

        return query select true, 'SESSION_ALREADY_MISSING_OR_STALE'::text;
        return;
    end if;

    insert into session_logout_events(
        account_id,
        access_token_hash,
        logout_scope,
        reason,
        completed,
        code)
    values(
        p_accountId,
        p_accessTokenHash,
        'current',
        p_reason,
        true,
        'CURRENT_SESSION_LOGGED_OUT');

    return query select true, 'CURRENT_SESSION_LOGGED_OUT'::text;
end;
$$;

create or replace function logout_all_sessions(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_reason text default 'logout-all')
returns table(result boolean, code text, account_security_stamp uuid)
language plpgsql
as $$
declare
    newStamp uuid := gen_random_uuid();
begin
    update accounts
       set security_stamp = newStamp,
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    if not found then
        insert into session_logout_events(
            account_id,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            'all',
            p_reason,
            false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH');

        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId;

    delete from pending_two_factor_sessions
     where account_id = p_accountId;

    insert into session_logout_events(
        account_id,
        logout_scope,
        reason,
        completed,
        code)
    values(
        p_accountId,
        'all',
        p_reason,
        true,
        'ALL_SESSIONS_LOGGED_OUT');

    return query select true, 'ALL_SESSIONS_LOGGED_OUT'::text, newStamp;
end;
$$;


create or replace function list_active_sessions(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_currentAccessTokenHash text)
returns table(
    session_id uuid,
    created_on timestamp with time zone,
    access_expiration timestamp with time zone,
    session_expiration timestamp with time zone,
    features smallint,
    is_current boolean)
language sql
stable
as $$
    select s.session_id,
           s.created_on,
           s.access_expiration,
           s.session_expiration,
           coalesce(s.features, 0)::smallint,
           s.access_token_hash = p_currentAccessTokenHash as is_current
      from sessions s
      join accounts a on a.account_id = s.account_id
     where s.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
       and s.account_security_stamp = a.security_stamp
       and s.session_expiration > now()
       and (case
                when s.cut_off is null then a.cut_off
                when a.cut_off is null then s.cut_off
                else least(s.cut_off, a.cut_off)
            end is null
            or case
                when s.cut_off is null then a.cut_off
                when a.cut_off is null then s.cut_off
                else least(s.cut_off, a.cut_off)
            end > now())
     order by is_current desc,
              s.created_on desc nulls last,
              s.session_expiration desc,
              s.session_id desc;
$$;

create or replace function revoke_session_for_account(
    p_accountId uuid,
    p_targetSessionId uuid,
    p_accountSecurityStamp uuid,
    p_currentAccessTokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    targetAccessTokenHash text;
begin
    if not exists (
        select 1
          from accounts a
         where a.account_id = p_accountId
           and a.security_stamp = p_accountSecurityStamp
    ) then
        insert into session_logout_events(
            account_id,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            'session',
            'session-management-revoke',
            false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH');

        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    select s.access_token_hash
      into targetAccessTokenHash
      from sessions s
     where s.account_id = p_accountId
       and s.session_id = p_targetSessionId
       and s.account_security_stamp = p_accountSecurityStamp
       and s.session_expiration > now()
     for update;

    if not found then
        insert into session_logout_events(
            account_id,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            'session',
            'session-management-revoke',
            true,
            'SESSION_ALREADY_MISSING_OR_STALE');

        return query select true, 'SESSION_ALREADY_MISSING_OR_STALE'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and session_id = p_targetSessionId
       and account_security_stamp = p_accountSecurityStamp;

    insert into session_logout_events(
        account_id,
        access_token_hash,
        logout_scope,
        reason,
        completed,
        code)
    values(
        p_accountId,
        targetAccessTokenHash,
        'session',
        'session-management-revoke',
        true,
        case
            when targetAccessTokenHash = p_currentAccessTokenHash then 'CURRENT_SESSION_REVOKED'
            else 'SESSION_REVOKED'
        end);

    return query select true,
        case
            when targetAccessTokenHash = p_currentAccessTokenHash then 'CURRENT_SESSION_REVOKED'::text
            else 'SESSION_REVOKED'::text
        end;
end;
$$;

create or replace function get_twofactor_details(p_accountId uuid)
returns table(
    method smallint,
    auth_id text,
    phone_number text,
    phone_country_code text,
    email_address text)
language sql
stable
as $$
    select t.method,
           t.auth_id,
           t.phone_number,
           t.phone_country_code,
           case when t.method = 1 then a.email_address else t.email_address end as email_address
      from two_factor_authentications t
      join accounts a on a.account_id = t.account_id
     where t.account_id = p_accountId
       and t.verified = true
       and t.revoked_at is null
       and (t.expiration is null or t.expiration > now())
       and (
            t.method <> 3
            or (
                t.revoked_at is null
                and t.totp_provider_type = 1
                and t.totp_secret_ciphertext is not null
                and octet_length(t.totp_secret_ciphertext) > 0
                and t.totp_secret_nonce is not null
                and octet_length(t.totp_secret_nonce) > 0
                and t.totp_secret_tag is not null
                and octet_length(t.totp_secret_tag) > 0
                and coalesce(t.totp_secret_version, 0) > 0
            )
       )
     order by t.priority desc,
              t.two_factor_index asc;
$$;

create or replace function begin_twofactor_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_tokenHash text,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_emailAddress text,
    p_phoneNumber text,
    p_phoneCountryCode text,
    p_authId text,
    p_required boolean)
returns table(result boolean, code text, two_factor_index smallint, expiration timestamp with time zone)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    target_index smallint;
    requested_email text := nullif(lower(trim(p_emailAddress)), '');
    normalized_email text;
    normalized_phone text := nullif(trim(p_phoneNumber), '');
    normalized_phone_country text := nullif(trim(p_phoneCountryCode), '');
    normalized_auth_id text := nullif(trim(p_authId), '');
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::smallint, null::timestamp with time zone;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::smallint, null::timestamp with time zone;
        return;
    end if;

    if p_method not in (1, 2) then
        return query select false, 'TWO_FACTOR_SETUP_UNSUPPORTED_METHOD'::text, null::smallint, null::timestamp with time zone;
        return;
    end if;

    if p_tokenHash is null or length(trim(p_tokenHash)) = 0 then
        return query select false, 'TWO_FACTOR_SETUP_INVALID_TOKEN'::text, null::smallint, null::timestamp with time zone;
        return;
    end if;

    if p_createdOn is null or p_expiration is null or p_expiration <= p_createdOn then
        return query select false, 'TWO_FACTOR_SETUP_INVALID_EXPIRATION'::text, null::smallint, null::timestamp with time zone;
        return;
    end if;

    if p_method = 1 then
        normalized_email := nullif(lower(trim(account_record.email_address)), '');

        if normalized_email is null then
            return query select false, 'TWO_FACTOR_SETUP_ACCOUNT_EMAIL_UNAVAILABLE'::text, null::smallint, null::timestamp with time zone;
            return;
        end if;

        if requested_email is not null and requested_email <> normalized_email then
            return query select false, 'TWO_FACTOR_SETUP_EMAIL_MISMATCH'::text, null::smallint, null::timestamp with time zone;
            return;
        end if;
    end if;

    if p_method = 2 and (normalized_phone is null or normalized_phone_country is null) then
        return query select false, 'TWO_FACTOR_SETUP_INVALID_DESTINATION'::text, null::smallint, null::timestamp with time zone;
        return;
    end if;

    if exists (
        select 1
          from two_factor_authentications t
         where t.account_id = p_accountId
           and t.method = p_method
           and t.verified = true
           and t.revoked_at is null
    ) then
        return query select false, 'TWO_FACTOR_SETUP_DUPLICATE'::text, null::smallint, null::timestamp with time zone;
        return;
    end if;

    -- The public setup-verification request carries method + code, not destination.
    -- Keep one pending setup per account regardless of method so attempt accounting is unambiguous.
    -- A newer setup request replaces the previous pending destination/code/method for the account.
    select t.two_factor_index
      into target_index
      from two_factor_authentications t
     where t.account_id = p_accountId
       and t.verified = false
       and t.revoked_at is null
     order by t.created_on desc, t.two_factor_index desc
     limit 1;

    if target_index is null then
        select (coalesce(max(t.two_factor_index), -1) + 1)::smallint
          into target_index
          from two_factor_authentications t
         where t.account_id = p_accountId;

        insert into two_factor_authentications(
            two_factor_index,
            account_id,
            token,
            auth_id,
            created_on,
            lifespan,
            expiration,
            method,
            verified,
            priority,
            country,
            email_address,
            phone_number,
            phone_country_code,
            required,
            setup_attempts)
        values (
            target_index,
            p_accountId,
            p_tokenHash,
            case when p_method = 3 then normalized_auth_id else null end,
            p_createdOn,
            p_expiration - p_createdOn,
            p_expiration,
            p_method,
            false,
            0,
            null,
            case when p_method = 1 then normalized_email else null end,
            case when p_method = 2 then normalized_phone else null end,
            case when p_method = 2 then normalized_phone_country else null end,
            coalesce(p_required, false),
            0);
    else
        update two_factor_authentications t
           set token = p_tokenHash,
               auth_id = case when p_method = 3 then normalized_auth_id else null end,
               created_on = p_createdOn,
               lifespan = p_expiration - p_createdOn,
               expiration = p_expiration,
               method = p_method,
               priority = 0,
               email_address = case when p_method = 1 then normalized_email else null end,
               phone_number = case when p_method = 2 then normalized_phone else null end,
               phone_country_code = case when p_method = 2 then normalized_phone_country else null end,
               required = coalesce(p_required, false),
               setup_attempts = 0
         where t.account_id = p_accountId
           and t.two_factor_index = target_index
           and t.verified = false
           and t.revoked_at is null;
    end if;

    delete from two_factor_authentications t
     where t.account_id = p_accountId
       and t.verified = false
       and t.revoked_at is null
       and t.two_factor_index <> target_index;

    return query select true, 'TWO_FACTOR_SETUP_PENDING'::text, target_index, p_expiration;
exception
    when unique_violation then
        return query select false, 'TWO_FACTOR_SETUP_DUPLICATE'::text, null::smallint, null::timestamp with time zone;
    when others then
        return query select false, 'TWO_FACTOR_SETUP_FAILED'::text, null::smallint, null::timestamp with time zone;
end;
$$;

create or replace function cancel_twofactor_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_tokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    deleted_count integer;
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    delete from two_factor_authentications
     where account_id = p_accountId
       and method = p_method
       and token = p_tokenHash
       and verified = false
       and revoked_at is null;

    get diagnostics deleted_count = row_count;

    return query select (deleted_count > 0),
        case when deleted_count > 0 then 'TWO_FACTOR_SETUP_CANCELLED' else 'TWO_FACTOR_SETUP_NOT_FOUND' end::text;
exception
    when others then
        return query select false, 'TWO_FACTOR_SETUP_CANCEL_FAILED'::text;
end;
$$;

create or replace function verify_twofactor_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_tokenHash text,
    p_maxAttempts integer,
    p_now timestamp with time zone)
returns table(result boolean, code text, attempts smallint, expiration timestamp with time zone)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    matching_setup two_factor_authentications%rowtype;
    pending_setup two_factor_authentications%rowtype;
    safe_max_attempts smallint := greatest(coalesce(p_maxAttempts, 1), 1)::smallint;
    next_attempts smallint;
    verified_count smallint;
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, 0::smallint, null::timestamp with time zone;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, 0::smallint, null::timestamp with time zone;
        return;
    end if;

    if p_method not in (1, 2) then
        return query select false, 'TWO_FACTOR_SETUP_UNSUPPORTED_METHOD'::text, 0::smallint, null::timestamp with time zone;
        return;
    end if;

    if p_tokenHash is null or length(trim(p_tokenHash)) = 0 then
        return query select false, 'TWO_FACTOR_SETUP_INVALID_TOKEN'::text, 0::smallint, null::timestamp with time zone;
        return;
    end if;

    select *
      into matching_setup
      from two_factor_authentications t
     where t.account_id = p_accountId
       and t.method = p_method
       and t.verified = false
       and t.revoked_at is null
       and t.token = p_tokenHash
     order by t.created_on desc, t.two_factor_index desc
     limit 1
     for update;

    if found then
        if matching_setup.expiration is not null and matching_setup.expiration <= p_now then
            update two_factor_authentications
               set token = null,
                   expiration = p_now,
                   lifespan = p_now - created_on,
                   setup_attempts = safe_max_attempts
             where account_id = p_accountId
               and two_factor_index = matching_setup.two_factor_index;

            return query select false, 'TWO_FACTOR_SETUP_EXPIRED'::text, safe_max_attempts, matching_setup.expiration;
            return;
        end if;

        if exists (
            select 1
              from two_factor_authentications t
             where t.account_id = p_accountId
               and t.method = p_method
               and t.verified = true
               and t.revoked_at is null
               and t.two_factor_index <> matching_setup.two_factor_index
        ) then
            return query select false, 'TWO_FACTOR_SETUP_DUPLICATE'::text, 0::smallint, null::timestamp with time zone;
            return;
        end if;

        update two_factor_authentications
           set verified = true,
               token = null,
               expiration = null,
               lifespan = null,
               setup_attempts = 0,
               priority = greatest(priority, 1)
         where account_id = p_accountId
           and two_factor_index = matching_setup.two_factor_index;

        select count(*)::smallint
          into verified_count
          from two_factor_authentications t
         where t.account_id = p_accountId
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > p_now);

        update accounts
           set two_factor_auth_method = p_method,
               two_auth_usage = greatest(verified_count, 1)::smallint
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp;

        return query select true, 'TWO_FACTOR_SETUP_VERIFIED'::text, 0::smallint, null::timestamp with time zone;
        return;
    end if;

    select *
      into pending_setup
      from two_factor_authentications t
     where t.account_id = p_accountId
       and t.method = p_method
       and t.verified = false
       and t.revoked_at is null
       and (t.expiration is null or t.expiration > p_now)
     order by t.created_on desc, t.two_factor_index desc
     limit 1
     for update;

    if not found then
        return query select false, 'TWO_FACTOR_SETUP_NOT_FOUND'::text, 0::smallint, null::timestamp with time zone;
        return;
    end if;

    next_attempts := least((pending_setup.setup_attempts + 1), safe_max_attempts)::smallint;

    update two_factor_authentications t
       set setup_attempts = next_attempts,
           token = case when next_attempts >= safe_max_attempts then null else t.token end,
           expiration = case when next_attempts >= safe_max_attempts then p_now else t.expiration end
     where t.account_id = p_accountId
       and t.two_factor_index = pending_setup.two_factor_index;

    if next_attempts >= safe_max_attempts then
        return query select false, 'TWO_FACTOR_SETUP_ATTEMPT_LIMIT'::text, next_attempts, p_now;
        return;
    end if;

    return query select false, 'TWO_FACTOR_SETUP_INCORRECT'::text, next_attempts, pending_setup.expiration;
exception
    when unique_violation then
        return query select false, 'TWO_FACTOR_SETUP_DUPLICATE'::text, 0::smallint, null::timestamp with time zone;
    when others then
        return query select false, 'TWO_FACTOR_SETUP_FAILED'::text, 0::smallint, null::timestamp with time zone;
end;
$$;


create or replace function remove_twofactor_method(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_now timestamp with time zone default now())
returns table(
    result boolean,
    code text,
    removed_method smallint,
    two_factor_methods smallint[],
    available_configurations smallint[])
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    moment timestamp with time zone := coalesce(p_now, now());
    revoked_count integer := 0;
    remaining_methods smallint[] := array[]::smallint[];
    remaining_configurations smallint[] := array[]::smallint[];
    selected_method smallint := 0;
    usage_count smallint := null;
    reset_session_revoke_result boolean := true;
    reset_session_revoke_code text := null;
begin
    select *
      into account_record
      from accounts a
     where a.account_id = p_accountId
     for update;

    if not found then
        return query select false,
            'ACCOUNT_NOT_FOUND'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    if p_method not in (1, 2, 3) then
        return query select false,
            'TWO_FACTOR_METHOD_REMOVE_UNSUPPORTED_METHOD'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    update two_factor_authentications t
       set verified = false,
           revoked_at = moment,
           revoked_reason = 'user_removed',
           token = null,
           auth_id = null,
           expiration = moment,
           lifespan = case when t.created_on is null then t.lifespan else moment - t.created_on end,
           totp_secret_ciphertext = case when p_method = 3 then null else t.totp_secret_ciphertext end,
           totp_secret_nonce = case when p_method = 3 then null else t.totp_secret_nonce end,
           totp_secret_tag = case when p_method = 3 then null else t.totp_secret_tag end,
           totp_last_used_step = case when p_method = 3 then null else t.totp_last_used_step end,
           totp_provider_enrollment_id = case when p_method = 3 then null else t.totp_provider_enrollment_id end,
           totp_provider_account_binding_hash = case when p_method = 3 then null else t.totp_provider_account_binding_hash end
     where t.account_id = p_accountId
       and t.method = p_method
       and t.verified = true
       and t.revoked_at is null;

    get diagnostics revoked_count = row_count;

    delete from two_factor_authentications t
     where t.account_id = p_accountId
       and t.method = p_method
       and t.verified = false
       and t.revoked_at is null;

    if revoked_count = 0 then
        select coalesce(array_agg(method order by method), array[]::smallint[])
          into remaining_methods
          from (
              select distinct t.method::smallint as method
                from two_factor_authentications t
                join accounts a on a.account_id = t.account_id
               where t.account_id = p_accountId
                 and t.verified = true
                 and t.revoked_at is null
                 and (t.expiration is null or t.expiration > moment)
                 and (
                    (t.method = 1 and nullif(trim(a.email_address), '') is not null)
                    or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
                    or (
                        t.method = 3
                        and t.totp_provider_type = 1
                        and t.totp_secret_ciphertext is not null
                        and octet_length(t.totp_secret_ciphertext) > 0
                        and t.totp_secret_nonce is not null
                        and octet_length(t.totp_secret_nonce) > 0
                        and t.totp_secret_tag is not null
                        and octet_length(t.totp_secret_tag) > 0
                        and coalesce(t.totp_secret_version, 0) > 0
                    )
                 )
          ) usable;

        remaining_configurations := resolve_available_twofactor_configurations(p_accountId);
        return query select false,
            'TWO_FACTOR_METHOD_NOT_CONFIGURED'::text,
            p_method::smallint,
            coalesce(remaining_methods, array[]::smallint[]),
            coalesce(remaining_configurations, array[]::smallint[]);
        return;
    end if;

    delete from pending_two_factor_sessions p
     where p.account_id = p_accountId;

    select r.result, r.code
      into reset_session_revoke_result, reset_session_revoke_code
      from revoke_pending_password_reset_sessions_for_account(
        p_accountId,
        moment,
        'PASSWORD_RESET_SESSION_REVOKED_BY_TWO_FACTOR_METHOD_REMOVAL') r
     limit 1;

    if coalesce(reset_session_revoke_result, false) = false then
        return query select false,
            'TWO_FACTOR_METHOD_REMOVE_FAILED'::text,
            p_method::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    select coalesce(array_agg(method order by method), array[]::smallint[])
      into remaining_methods
      from (
          select distinct t.method::smallint as method
            from two_factor_authentications t
            join accounts a on a.account_id = t.account_id
           where t.account_id = p_accountId
             and t.verified = true
             and t.revoked_at is null
             and (t.expiration is null or t.expiration > moment)
             and (
                (t.method = 1 and nullif(trim(a.email_address), '') is not null)
                or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
                or (
                    t.method = 3
                    and t.totp_provider_type = 1
                    and t.totp_secret_ciphertext is not null
                    and octet_length(t.totp_secret_ciphertext) > 0
                    and t.totp_secret_nonce is not null
                    and octet_length(t.totp_secret_nonce) > 0
                    and t.totp_secret_tag is not null
                    and octet_length(t.totp_secret_tag) > 0
                    and coalesce(t.totp_secret_version, 0) > 0
                )
             )
      ) usable;

    remaining_configurations := resolve_available_twofactor_configurations(p_accountId);
    usage_count := nullif(cardinality(coalesce(remaining_methods, array[]::smallint[])), 0)::smallint;
    selected_method := coalesce((select method_value from unnest(coalesce(remaining_methods, array[]::smallint[])) as remaining(method_value) order by method_value limit 1), 0)::smallint;

    update accounts a
       set two_factor_auth_method = selected_method,
           two_auth_usage = usage_count
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp;

    return query select true,
        'TWO_FACTOR_METHOD_REMOVED'::text,
        p_method::smallint,
        coalesce(remaining_methods, array[]::smallint[]),
        coalesce(remaining_configurations, array[]::smallint[]);
exception
    when others then
        return query select false,
            'TWO_FACTOR_METHOD_REMOVE_FAILED'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
end;
$$;


create or replace function begin_authenticator_app_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_authId text,
    p_required boolean,
    p_totpProviderType smallint,
    p_totpSecretCiphertext bytea,
    p_totpSecretNonce bytea,
    p_totpSecretTag bytea,
    p_totpSecretVersion integer)
returns table(result boolean, code text, two_factor_index smallint, expiration timestamp with time zone)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    target_index smallint;
    provider_type smallint := coalesce(p_totpProviderType, 1)::smallint;
    moment timestamp with time zone := coalesce(p_createdOn, now());
begin
    select * into account_record from accounts where account_id = p_accountId for update;
    if not found then return query select false, 'ACCOUNT_NOT_FOUND'::text, null::smallint, null::timestamp with time zone; return; end if;
    if account_record.security_stamp <> p_accountSecurityStamp then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::smallint, null::timestamp with time zone; return; end if;
    if account_record.verify_status <> 1 then return query select false, 'ACCOUNT_NOT_VERIFIED'::text, null::smallint, null::timestamp with time zone; return; end if;
    if account_record.cut_off is not null and account_record.cut_off <= moment then return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text, null::smallint, null::timestamp with time zone; return; end if;
    if provider_type <> 1 then return query select false, 'AUTHENTICATOR_SETUP_UNSUPPORTED_PROVIDER'::text, null::smallint, null::timestamp with time zone; return; end if;
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text, null::smallint, null::timestamp with time zone; return; end if;
    if p_createdOn is null or p_expiration is null or p_expiration <= p_createdOn or p_expiration <= now() then return query select false, 'AUTHENTICATOR_SETUP_INVALID_EXPIRATION'::text, null::smallint, null::timestamp with time zone; return; end if;
    if p_totpSecretCiphertext is null or octet_length(p_totpSecretCiphertext) = 0 or p_totpSecretNonce is null or octet_length(p_totpSecretNonce) = 0 or p_totpSecretTag is null or octet_length(p_totpSecretTag) = 0 or coalesce(p_totpSecretVersion, 0) <= 0 then return query select false, 'AUTHENTICATOR_SETUP_INVALID_SECRET'::text, null::smallint, null::timestamp with time zone; return; end if;
    if exists (select 1 from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = true and t.revoked_at is null) then return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::smallint, null::timestamp with time zone; return; end if;

    select t.two_factor_index into target_index from two_factor_authentications t where t.account_id = p_accountId and t.verified = false and t.revoked_at is null order by t.created_on desc, t.two_factor_index desc limit 1 for update;
    if target_index is null then
        select (coalesce(max(t.two_factor_index), -1) + 1)::smallint into target_index from two_factor_authentications t where t.account_id = p_accountId;
        insert into two_factor_authentications(two_factor_index, account_id, token, auth_id, created_on, lifespan, expiration, method, verified, priority, country, email_address, phone_number, phone_country_code, required, totp_secret_ciphertext, totp_secret_nonce, totp_secret_tag, totp_secret_version, totp_last_used_step, totp_provider_type, totp_provider_enrollment_id, totp_provider_account_binding_hash, setup_attempts, revoked_at, revoked_reason)
        values(target_index, p_accountId, p_setupTokenHash, nullif(trim(p_authId), ''), p_createdOn, p_expiration - p_createdOn, p_expiration, 3, false, 0, null, null, null, null, coalesce(p_required, true), p_totpSecretCiphertext, p_totpSecretNonce, p_totpSecretTag, p_totpSecretVersion, null, provider_type, null, null, 0, null, null);
    else
        update two_factor_authentications set token = p_setupTokenHash, auth_id = nullif(trim(p_authId), ''), created_on = p_createdOn, lifespan = p_expiration - p_createdOn, expiration = p_expiration, method = 3, verified = false, priority = 0, country = null, email_address = null, phone_number = null, phone_country_code = null, required = coalesce(p_required, true), totp_secret_ciphertext = p_totpSecretCiphertext, totp_secret_nonce = p_totpSecretNonce, totp_secret_tag = p_totpSecretTag, totp_secret_version = p_totpSecretVersion, totp_last_used_step = null, totp_provider_type = provider_type, totp_provider_enrollment_id = null, totp_provider_account_binding_hash = null, setup_attempts = 0, revoked_at = null, revoked_reason = null where account_id = p_accountId and two_factor_index = target_index and verified = false and revoked_at is null;
    end if;
    delete from two_factor_authentications t where t.account_id = p_accountId and t.verified = false and t.revoked_at is null and t.two_factor_index <> target_index;
    return query select true, 'AUTHENTICATOR_SETUP_PENDING'::text, target_index, p_expiration;
exception when unique_violation then
    return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::smallint, null::timestamp with time zone;
when others then
    return query select false, 'AUTHENTICATOR_SETUP_FAILED'::text, null::smallint, null::timestamp with time zone;
end;
$$;

create or replace function get_pending_authenticator_app_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_now timestamp with time zone)
returns table(result boolean, code text, two_factor_index smallint, expiration timestamp with time zone, setup_attempts smallint, totp_secret_ciphertext bytea, totp_secret_nonce bytea, totp_secret_tag bytea, totp_secret_version integer, totp_last_used_step bigint, totp_provider_type smallint)
language plpgsql
stable
as $$
begin
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text, null::smallint, null::timestamp with time zone, 0::smallint, null::bytea, null::bytea, null::bytea, null::integer, null::bigint, null::smallint; return; end if;
    if not exists (select 1 from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp and a.verify_status = 1 and (a.cut_off is null or a.cut_off > coalesce(p_now, now()))) then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::smallint, null::timestamp with time zone, 0::smallint, null::bytea, null::bytea, null::bytea, null::integer, null::bigint, null::smallint; return; end if;
    return query select true, 'AUTHENTICATOR_SETUP_FOUND'::text, t.two_factor_index, t.expiration, t.setup_attempts, t.totp_secret_ciphertext, t.totp_secret_nonce, t.totp_secret_tag, t.totp_secret_version, t.totp_last_used_step, t.totp_provider_type from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash and (t.expiration is null or t.expiration > coalesce(p_now, now())) and t.totp_provider_type = 1 and t.totp_secret_ciphertext is not null and t.totp_secret_nonce is not null and t.totp_secret_tag is not null order by t.created_on desc, t.two_factor_index desc limit 1;
    if not found then return query select false, 'AUTHENTICATOR_SETUP_NOT_FOUND'::text, null::smallint, null::timestamp with time zone, 0::smallint, null::bytea, null::bytea, null::bytea, null::integer, null::bigint, null::smallint; end if;
end;
$$;

create or replace function record_authenticator_app_setup_failure(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_maxAttempts smallint,
    p_now timestamp with time zone)
returns table(result boolean, code text, attempts smallint, expiration timestamp with time zone)
language plpgsql
as $$
declare
    setup_record two_factor_authentications%rowtype;
    safe_max_attempts smallint := greatest(coalesce(p_maxAttempts, 1), 1)::smallint;
    next_attempts smallint;
    moment timestamp with time zone := coalesce(p_now, now());
begin
    if not exists (select 1 from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp and a.verify_status = 1 and (a.cut_off is null or a.cut_off > moment)) then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, 0::smallint, null::timestamp with time zone; return; end if;
    select * into setup_record from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash order by t.created_on desc, t.two_factor_index desc limit 1 for update;
    if not found then return query select false, 'AUTHENTICATOR_SETUP_NOT_FOUND'::text, 0::smallint, null::timestamp with time zone; return; end if;
    if setup_record.expiration is not null and setup_record.expiration <= moment then
        update two_factor_authentications set token = null, expiration = moment, lifespan = moment - created_on, setup_attempts = safe_max_attempts, totp_secret_ciphertext = null, totp_secret_nonce = null, totp_secret_tag = null where account_id = p_accountId and two_factor_index = setup_record.two_factor_index;
        return query select false, 'AUTHENTICATOR_SETUP_EXPIRED'::text, safe_max_attempts, setup_record.expiration; return;
    end if;
    next_attempts := least(setup_record.setup_attempts + 1, safe_max_attempts)::smallint;
    update two_factor_authentications t
       set setup_attempts = next_attempts,
           token = case when next_attempts >= safe_max_attempts then null else t.token end,
           expiration = case when next_attempts >= safe_max_attempts then moment else t.expiration end,
           totp_secret_ciphertext = case when next_attempts >= safe_max_attempts then null else t.totp_secret_ciphertext end,
           totp_secret_nonce = case when next_attempts >= safe_max_attempts then null else t.totp_secret_nonce end,
           totp_secret_tag = case when next_attempts >= safe_max_attempts then null else t.totp_secret_tag end
     where t.account_id = p_accountId
       and t.two_factor_index = setup_record.two_factor_index;
    if next_attempts >= safe_max_attempts then return query select false, 'AUTHENTICATOR_SETUP_ATTEMPT_LIMIT'::text, next_attempts, moment; return; end if;
    return query select false, 'AUTHENTICATOR_SETUP_INCORRECT'::text, next_attempts, setup_record.expiration;
exception when others then
    return query select false, 'AUTHENTICATOR_SETUP_FAILURE_RECORD_FAILED'::text, 0::smallint, null::timestamp with time zone;
end;
$$;

create or replace function complete_authenticator_app_setup_and_rotate_session(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_timeStep bigint,
    p_expectedOldAccessTokenHash text,
    p_newAccessTokenHash text,
    p_refreshToken bytea,
    p_refreshes smallint,
    p_refreshLimit smallint,
    p_createdOn timestamp with time zone,
    p_sessionLifespan interval,
    p_accessExpiration timestamp with time zone,
    p_sessionExpiration timestamp with time zone,
    p_cutOff timestamp with time zone,
    p_features smallint,
    p_sessionSecurityStamp uuid)
returns table(result boolean, code text, account_security_stamp uuid, two_factor_index smallint)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    setup_record two_factor_authentications%rowtype;
    old_session sessions%rowtype;
    old_cutoff timestamp with time zone;
    new_cutoff timestamp with time zone;
    moment timestamp with time zone := coalesce(p_createdOn, now());
    new_account_stamp uuid := gen_random_uuid();
    verified_count smallint;
begin
    if p_timeStep is null or p_timeStep < 0 then return query select false, 'TOTP_INVALID_TIME_STEP'::text, null::uuid, null::smallint; return; end if;
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then return query select false, 'NEW_SESSION_CONFLICT'::text, null::uuid, null::smallint; return; end if;
    if p_accessExpiration is null or p_sessionExpiration is null or p_accessExpiration <= moment or p_sessionExpiration <= moment or p_accessExpiration > p_sessionExpiration then return query select false, 'SESSION_EXPIRATION_INVALID'::text, null::uuid, null::smallint; return; end if;
    select * into account_record from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp for update;
    if not found then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid, null::smallint; return; end if;
    if account_record.verify_status <> 1 then return query select false, 'ACCOUNT_NOT_VERIFIED'::text, null::uuid, null::smallint; return; end if;
    if account_record.cut_off is not null and account_record.cut_off <= moment then return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text, null::uuid, null::smallint; return; end if;
    select * into old_session from sessions s where s.account_id = p_accountId and s.access_token_hash = p_expectedOldAccessTokenHash and s.account_security_stamp = p_accountSecurityStamp for update;
    if not found then return query select false, 'OLD_SESSION_NOT_FOUND'::text, null::uuid, null::smallint; return; end if;
    old_cutoff := case when old_session.cut_off is null then account_record.cut_off when account_record.cut_off is null then old_session.cut_off else least(old_session.cut_off, account_record.cut_off) end;
    if old_session.session_expiration <= moment or old_session.access_expiration <= moment or (old_cutoff is not null and old_cutoff <= moment) then return query select false, 'OLD_SESSION_EXPIRED'::text, null::uuid, null::smallint; return; end if;
    select * into setup_record from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash order by t.created_on desc, t.two_factor_index desc limit 1 for update;
    if not found then return query select false, 'AUTHENTICATOR_SETUP_NOT_FOUND'::text, null::uuid, null::smallint; return; end if;
    if setup_record.expiration is not null and setup_record.expiration <= moment then return query select false, 'AUTHENTICATOR_SETUP_EXPIRED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if setup_record.totp_provider_type <> 1 or setup_record.totp_secret_ciphertext is null or setup_record.totp_secret_nonce is null or setup_record.totp_secret_tag is null then return query select false, 'AUTHENTICATOR_SETUP_INVALID_SECRET'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if setup_record.totp_last_used_step is not null and p_timeStep <= setup_record.totp_last_used_step then return query select false, 'TOTP_REPLAY_DETECTED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if exists (select 1 from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = true and t.revoked_at is null and t.two_factor_index <> setup_record.two_factor_index) then return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    new_cutoff := case when p_cutOff is null then account_record.cut_off when account_record.cut_off is null then p_cutOff else least(p_cutOff, account_record.cut_off) end;
    if new_cutoff is not null and new_cutoff <= moment then return query select false, 'SESSION_CUT_OFF_EXPIRED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    update two_factor_authentications tfa set verified = true, token = null, expiration = null, lifespan = null, setup_attempts = 0, priority = greatest(tfa.priority, 1), totp_last_used_step = p_timeStep, revoked_at = null, revoked_reason = null where tfa.account_id = p_accountId and tfa.two_factor_index = setup_record.two_factor_index and tfa.verified = false and tfa.revoked_at is null;
    select count(*)::smallint
      into verified_count
      from two_factor_authentications t
     where t.account_id = p_accountId
       and t.verified = true
       and t.revoked_at is null
       and (t.expiration is null or t.expiration > moment)
       and (
            t.method in (1, 2)
            or (
                t.method = 3
                and t.revoked_at is null
                and t.totp_provider_type = 1
                and t.totp_secret_ciphertext is not null
                and octet_length(t.totp_secret_ciphertext) > 0
                and t.totp_secret_nonce is not null
                and octet_length(t.totp_secret_nonce) > 0
                and t.totp_secret_tag is not null
                and octet_length(t.totp_secret_tag) > 0
                and coalesce(t.totp_secret_version, 0) > 0
            )
       );
    update accounts a set security_stamp = new_account_stamp, two_factor_auth_method = 3, two_auth_usage = greatest(verified_count, 1)::smallint where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp;
    update sessions set access_expiration = least(access_expiration, greatest(created_on, moment)), session_expiration = least(session_expiration, greatest(created_on, moment)) where account_id = p_accountId and session_expiration > moment;
    insert into sessions(access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, cut_off, features, security_stamp, account_security_stamp) values(p_newAccessTokenHash, p_accountId, p_refreshToken, coalesce(p_refreshes, 0), coalesce(p_refreshLimit, 0), moment, p_sessionLifespan, p_accessExpiration, p_sessionExpiration, new_cutoff, coalesce(p_features, 0), p_sessionSecurityStamp, new_account_stamp);
    delete from pending_two_factor_sessions ptfs where ptfs.account_id = p_accountId;
    return query select true, 'AUTHENTICATOR_SETUP_VERIFIED_SESSION_ROTATED'::text, new_account_stamp, setup_record.two_factor_index;
exception when unique_violation then
    return query select false, 'NEW_SESSION_CONFLICT'::text, null::uuid, null::smallint;
when others then raise;
end;
$$;

create or replace function cancel_authenticator_app_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
declare deleted_count integer;
begin
    if not exists (select 1 from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp) then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text; return; end if;
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text; return; end if;
    delete from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash;
    get diagnostics deleted_count = row_count;
    return query select true, case when deleted_count > 0 then 'AUTHENTICATOR_SETUP_CANCELLED' else 'AUTHENTICATOR_SETUP_ALREADY_CANCELLED_OR_MISSING' end::text;
exception when others then
    return query select false, 'AUTHENTICATOR_SETUP_CANCEL_FAILED'::text;
end;
$$;

create or replace function get_verified_totp_enrollment_for_account(
    p_accountId uuid,
    p_now timestamp with time zone)
returns table(account_id uuid, two_factor_index smallint, method smallint, totp_provider_type smallint, totp_provider_enrollment_id text, totp_provider_account_binding_hash text, totp_secret_ciphertext bytea, totp_secret_nonce bytea, totp_secret_tag bytea, totp_secret_version integer, totp_last_used_step bigint)
language sql
stable
as $$
    select t.account_id, t.two_factor_index, t.method, t.totp_provider_type, t.totp_provider_enrollment_id, t.totp_provider_account_binding_hash, t.totp_secret_ciphertext, t.totp_secret_nonce, t.totp_secret_tag, t.totp_secret_version, t.totp_last_used_step
      from two_factor_authentications t
     where t.account_id = p_accountId
       and t.method = 3
       and t.verified = true
       and t.revoked_at is null
       and (t.expiration is null or t.expiration > coalesce(p_now, now()))
       and ((t.totp_provider_type = 1 and t.totp_secret_ciphertext is not null and t.totp_secret_nonce is not null and t.totp_secret_tag is not null) or (t.totp_provider_type = 2 and t.totp_provider_enrollment_id is not null and t.totp_provider_account_binding_hash is not null))
     order by t.required desc, t.priority asc, t.two_factor_index asc
     limit 1;
$$;

create or replace function mark_totp_step_used(
    p_accountId uuid,
    p_twoFactorIndex smallint,
    p_timeStep bigint)
returns table(result boolean, code text)
language plpgsql
as $$
declare existing_step bigint; provider_type smallint;
begin
    if p_timeStep is null or p_timeStep < 0 then return query select false, 'TOTP_INVALID_TIME_STEP'::text; return; end if;
    select t.totp_last_used_step, t.totp_provider_type into existing_step, provider_type from two_factor_authentications t where t.account_id = p_accountId and t.two_factor_index = p_twoFactorIndex and t.method = 3 and t.verified = true and t.revoked_at is null for update;
    if not found then return query select false, 'TOTP_ENROLLMENT_NOT_FOUND'::text; return; end if;
    if provider_type <> 1 then return query select false, 'TOTP_PROVIDER_MANAGED_NOT_LOCAL'::text; return; end if;
    if existing_step is not null and p_timeStep <= existing_step then return query select false, 'TOTP_REPLAY_DETECTED'::text; return; end if;
    update two_factor_authentications t set totp_last_used_step = p_timeStep where t.account_id = p_accountId and t.two_factor_index = p_twoFactorIndex and t.method = 3 and t.verified = true and t.revoked_at is null and t.totp_provider_type = 1;
    return query select true, 'TOTP_STEP_ACCEPTED'::text;
end;
$$;

create or replace function verify_account_delete_token(p_deleteTokenHash text)
returns table(result boolean, code text, workflow smallint)
language plpgsql
as $$
declare
    delete_record delete_standby%rowtype;
    resolved_workflow smallint;
begin
    if p_deleteTokenHash is null or length(trim(p_deleteTokenHash)) = 0 then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, 0::smallint;
        return;
    end if;

    select *
      into delete_record
      from delete_standby
     where delete_token_hash = p_deleteTokenHash
     for update;

    if not found then
        return query select false, 'ACCOUNT_DELETE_TOKEN_MISMATCH'::text, 0::smallint;
        return;
    end if;

    if delete_record.expiration <= now() then
        insert into account_delete_events(account_id, event_type, code)
        values (delete_record.account_id, 'VERIFY_FAILED', 'ACCOUNT_DELETE_TOKEN_EXPIRED');

        return query select false, 'ACCOUNT_DELETE_TOKEN_EXPIRED'::text, 0::smallint;
        return;
    end if;

    update delete_standby
       set verified = true
     where account_id = delete_record.account_id
       and delete_token_hash = p_deleteTokenHash;

    insert into account_delete_events(account_id, event_type, code)
    values (delete_record.account_id, 'VERIFIED', 'ACCOUNT_DELETE_VERIFIED');

    resolved_workflow := case
        when delete_record.pass_phrase_hash is null then 1::smallint
        else 2::smallint
    end;

    return query select true, 'ACCOUNT_DELETE_VERIFIED'::text, resolved_workflow;
end;
$$;

create or replace function purge_expired_delete_standby(
    p_now timestamp with time zone default now())
returns table(result boolean, code text, deleted_count integer)
language plpgsql
as $$
declare
    affected_rows integer;
begin
    with purged as (
        delete from delete_standby
         where expiration <= p_now
            or (finalize_locked_until is not null and finalize_locked_until <= p_now and expiration <= p_now)
         returning account_id
    ), audited as (
        insert into account_delete_events(account_id, event_type, code)
        select account_id, 'PURGED', 'ACCOUNT_DELETE_PURGE_SUCCEEDED'
          from purged
        returning 1
    )
    select count(*)::integer into affected_rows from audited;

    return query select true, 'ACCOUNT_DELETE_PURGE_SUCCEEDED'::text, affected_rows;
exception
    when others then
        return query select false, 'ACCOUNT_DELETE_PURGE_FAILED'::text, 0;
end;
$$;

create or replace function view_account(
    p_accountId uuid,
    p_accountSecurityStamp uuid)
returns table(
    result boolean,
    code text,
    email_address text,
    username text,
    created_on timestamp with time zone,
    verify_status smallint,
    country smallint,
    features smallint,
    two_factor_enabled boolean,
    two_factor_configuration smallint,
    two_factor_methods smallint[])
language plpgsql
stable
as $$
declare
    account_record accounts%rowtype;
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select
            false,
            'ACCOUNT_NOT_FOUND'::text,
            null::text,
            null::text,
            null::timestamp with time zone,
            null::smallint,
            null::smallint,
            null::smallint,
            false,
            0::smallint,
            array[]::smallint[];
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select
            false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,
            null::text,
            null::text,
            null::timestamp with time zone,
            null::smallint,
            null::smallint,
            null::smallint,
            false,
            0::smallint,
            array[]::smallint[];
        return;
    end if;

    return query
    with usable_methods as (
        select distinct t.method::smallint as method
          from two_factor_authentications t
         where t.account_id = p_accountId
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > now())
           and (
                (t.method = 1 and nullif(trim(account_record.email_address), '') is not null)
                or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
                or (
                    t.method = 3
                    and t.revoked_at is null
                    and t.totp_provider_type = 1
                    and t.totp_secret_ciphertext is not null
                    and octet_length(t.totp_secret_ciphertext) > 0
                    and t.totp_secret_nonce is not null
                    and octet_length(t.totp_secret_nonce) > 0
                    and t.totp_secret_tag is not null
                    and octet_length(t.totp_secret_tag) > 0
                    and coalesce(t.totp_secret_version, 0) > 0
                )
           )
    ), method_summary as (
        select coalesce(array_agg(method order by method), array[]::smallint[]) as methods,
               coalesce(bool_or(method = 1), false) as has_email,
               coalesce(bool_or(method = 2), false) as has_sms,
               coalesce(bool_or(method = 3), false) as has_authenticator_app
          from usable_methods
    )
    select
        true,
        'ACCOUNT_VIEW_SUCCEEDED'::text,
        account_record.email_address,
        account_record.username,
        account_record.created_on,
        account_record.verify_status,
        account_record.country,
        account_record.features,
        cardinality(method_summary.methods) > 0,
        case
            when method_summary.has_sms and not method_summary.has_email and not method_summary.has_authenticator_app then 1::smallint
            when method_summary.has_email and not method_summary.has_sms and not method_summary.has_authenticator_app then 2::smallint
            when method_summary.has_authenticator_app and not method_summary.has_email and not method_summary.has_sms then 3::smallint
            when method_summary.has_sms and method_summary.has_authenticator_app and not method_summary.has_email then 4::smallint
            when method_summary.has_email and method_summary.has_authenticator_app and not method_summary.has_sms then 5::smallint
            when cardinality(method_summary.methods) = 0 then 0::smallint
            else 6::smallint
        end,
        method_summary.methods
      from method_summary;
end;
$$;

create or replace function lookup_locked_recovery_account(
    p_identifier text,
    p_now timestamp with time zone)
returns table(
    result boolean,
    code text,
    account_id uuid,
    email_address text,
    phone_number text,
    phone_country_code text,
    account_security_stamp uuid,
    unlock_when timestamp with time zone)
language plpgsql
as $$
declare
    normalized_identifier text := lower(nullif(btrim(p_identifier), ''));
    account_record accounts%rowtype;
    v_phone_number text;
    v_phone_country_code text;
begin
    if normalized_identifier is null then
        return query select false, 'ACCOUNT_UNLOCK_NOT_LOCKED'::text, null::uuid, null::text, null::text, null::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    select *
      into account_record
      from accounts a
     where (lower(a.email_address) = normalized_identifier
        or lower(a.username) = normalized_identifier)
       and a.unlock_when is not null
       and a.unlock_when > p_now
     order by case when lower(a.email_address) = normalized_identifier then 0 else 1 end
     limit 1;

    if not found then
        return query select false, 'ACCOUNT_UNLOCK_NOT_LOCKED'::text, null::uuid, null::text, null::text, null::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    select t.phone_number, t.phone_country_code
      into v_phone_number, v_phone_country_code
      from two_factor_authentications t
     where t.account_id = account_record.account_id
       and t.method = 2
       and t.verified = true
       and t.revoked_at is null
       and t.phone_number is not null
       and (t.expiration is null or t.expiration > p_now)
     order by t.required desc, t.priority asc, t.two_factor_index asc
     limit 1;

    return query select
        true,
        'ACCOUNT_UNLOCK_ACCOUNT_FOUND'::text,
        account_record.account_id,
        account_record.email_address,
        v_phone_number,
        v_phone_country_code,
        account_record.security_stamp,
        account_record.unlock_when;
end;
$$;

create or replace function start_unlock_account(
    p_accountId uuid,
    p_tokenHash text,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_status smallint,
    p_method smallint,
    p_accountSecurityStamp uuid,
    p_lockoutUnlockWhen timestamp with time zone)
returns table(status smallint)
language plpgsql
as $$
declare
    v_security_stamp uuid;
    v_unlock_when timestamp with time zone;
begin
    if p_method not in (1, 2) then
        return query select 10::smallint;
        return;
    end if;

    select security_stamp, unlock_when
      into v_security_stamp, v_unlock_when
      from accounts
     where account_id = p_accountId;

    if not found or v_unlock_when is null or v_unlock_when <= p_createdOn then
        return query select 13::smallint;
        return;
    end if;

    if v_security_stamp is distinct from p_accountSecurityStamp
        or v_unlock_when is distinct from p_lockoutUnlockWhen then
        return query select 14::smallint;
        return;
    end if;

    update account_recoveries ar
       set status = 4
     where ar.account_id = p_accountId
       and ar.status in (1, 2, 3, 6);

    insert into account_recoveries(
        account_id,
        created_on,
        status,
        topic,
        expiration,
        token_hash,
        method,
        lockout_security_stamp,
        lockout_unlock_when)
    values(
        p_accountId,
        p_createdOn,
        p_status,
        1,
        p_expiration,
        p_tokenHash,
        p_method,
        p_accountSecurityStamp,
        p_lockoutUnlockWhen)
    on conflict (account_id, token_hash) do update
       set created_on = excluded.created_on,
           status = excluded.status,
           topic = excluded.topic,
           expiration = excluded.expiration,
           method = excluded.method,
           lockout_security_stamp = excluded.lockout_security_stamp,
           lockout_unlock_when = excluded.lockout_unlock_when;

    return query select p_status;
end;
$$;

create or replace function cancel_unlock_account(
    p_accountId uuid,
    p_tokenHash text)
returns table(status smallint)
language plpgsql
as $$
declare
    v_recovery account_recoveries%rowtype;
begin
    select *
      into v_recovery
      from account_recoveries ar
     where ar.account_id = p_accountId
       and ar.token_hash = p_tokenHash
     limit 1;

    if not found then
        return query select 9::smallint;
        return;
    end if;

    if v_recovery.status = 7 then
        return query select 11::smallint;
        return;
    end if;

    update account_recoveries ar
       set status = 4
     where ar.account_id = p_accountId
       and ar.token_hash = p_tokenHash;

    return query select 4::smallint;
end;
$$;

create or replace function verify_unlock_account(p_tokenHash text)
returns table(status smallint)
language plpgsql
as $$
declare
    v_recovery account_recoveries%rowtype;
    v_account_security_stamp uuid;
    v_account_unlock_when timestamp with time zone;
begin
    select *
      into v_recovery
      from account_recoveries ar
     where ar.token_hash = p_tokenHash
     order by ar.created_on desc
     limit 1;

    if not found then
        return query select 9::smallint;
        return;
    end if;

    if v_recovery.status = 7 then
        return query select 11::smallint;
        return;
    end if;

    if v_recovery.status = 4 then
        return query select 9::smallint;
        return;
    end if;

    if v_recovery.expiration <= now() then
        update account_recoveries ar
           set status = 5
         where ar.account_id = v_recovery.account_id
           and ar.token_hash = p_tokenHash;
        return query select 5::smallint;
        return;
    end if;

    if v_recovery.status not in (1, 2, 3, 6) then
        return query select 11::smallint;
        return;
    end if;

    select security_stamp, unlock_when
      into v_account_security_stamp, v_account_unlock_when
      from accounts
     where account_id = v_recovery.account_id;

    if not found
        or v_account_unlock_when is null
        or v_account_unlock_when <= now()
        or v_account_security_stamp is distinct from v_recovery.lockout_security_stamp
        or v_account_unlock_when is distinct from v_recovery.lockout_unlock_when then
        update account_recoveries ar
           set status = 14
         where ar.account_id = v_recovery.account_id
           and ar.token_hash = p_tokenHash;
        return query select 14::smallint;
        return;
    end if;

    update account_recoveries ar
       set status = 7
     where ar.account_id = v_recovery.account_id
       and ar.token_hash = p_tokenHash;

    update account_recoveries ar
       set status = 4
     where ar.account_id = v_recovery.account_id
       and ar.token_hash <> p_tokenHash
       and ar.status in (1, 2, 3, 6);

    update accounts
       set unlock_when = null,
           login_failures = 0
     where account_id = v_recovery.account_id;

    return query select 7::smallint;
end;
$$;



create or replace function lookup_password_reset_account(
    p_identifier text,
    p_now timestamp with time zone)
returns table(
    result boolean,
    code text,
    account_id uuid,
    email_address text,
    phone_number text,
    phone_country_code text,
    account_security_stamp uuid,
    email_verified boolean,
    sms_verified boolean,
    authenticator_verified boolean)
language plpgsql
as $$
declare
    normalized_identifier text := lower(nullif(btrim(p_identifier), ''));
    phone_identifier text := regexp_replace(coalesce(p_identifier, ''), '[^0-9+]', '', 'g');
    phone_identifier_digits text := regexp_replace(coalesce(p_identifier, ''), '[^0-9]', '', 'g');
    account_record accounts%rowtype;
    v_phone_number text;
    v_phone_country_code text;
    has_authenticator boolean := false;
begin
    if normalized_identifier is null then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, null::uuid, null::text, null::text, null::text, null::uuid, false, false, false;
        return;
    end if;

    select a.*
      into account_record
      from accounts a
     where lower(a.email_address) = normalized_identifier
        or lower(a.username) = normalized_identifier
        or exists (
            select 1
              from two_factor_authentications t
             where t.account_id = a.account_id
               and t.method = 2
               and t.verified = true
               and t.revoked_at is null
               and (t.expiration is null or t.expiration > p_now)
               and t.phone_number is not null
               and (
                    lower(t.phone_number) = normalized_identifier
                 or regexp_replace(coalesce(t.phone_number, ''), '[^0-9+]', '', 'g') = phone_identifier
                 or regexp_replace(coalesce(t.phone_country_code, '') || coalesce(t.phone_number, ''), '[^0-9+]', '', 'g') = phone_identifier
                 or regexp_replace(coalesce(t.phone_number, ''), '[^0-9]', '', 'g') = phone_identifier_digits
                 or regexp_replace(coalesce(t.phone_country_code, '') || coalesce(t.phone_number, ''), '[^0-9]', '', 'g') = phone_identifier_digits
               )
        )
     order by case
        when lower(a.email_address) = normalized_identifier then 0
        when lower(a.username) = normalized_identifier then 1
        else 2
     end
     limit 1;

    if not found then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, null::uuid, null::text, null::text, null::text, null::uuid, false, false, false;
        return;
    end if;

    select t.phone_number, t.phone_country_code
      into v_phone_number, v_phone_country_code
      from two_factor_authentications t
     where t.account_id = account_record.account_id
       and t.method = 2
       and t.verified = true
       and t.revoked_at is null
       and t.phone_number is not null
       and (t.expiration is null or t.expiration > p_now)
     order by t.required desc, t.priority asc, t.two_factor_index asc
     limit 1;

    has_authenticator := exists(
        select 1
          from two_factor_authentications t
         where t.account_id = account_record.account_id
           and t.method = 3
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > p_now)
           and t.totp_secret_ciphertext is not null
           and t.totp_secret_nonce is not null
           and t.totp_secret_tag is not null
    );

    return query select
        true,
        'PASSWORD_RESET_ACCOUNT_FOUND'::text,
        account_record.account_id,
        account_record.email_address,
        v_phone_number,
        v_phone_country_code,
        account_record.security_stamp,
        account_record.verify_status = 1,
        v_phone_number is not null,
        has_authenticator;
end;
$$;

create or replace function get_password_reset_totp_enrollment(
    p_accountId uuid,
    p_now timestamp with time zone)
returns table(
    account_id uuid,
    two_factor_index smallint,
    method smallint,
    totp_secret_ciphertext bytea,
    totp_secret_nonce bytea,
    totp_secret_tag bytea,
    totp_secret_version integer,
    totp_last_used_step bigint)
language sql
stable
as $$
    select e.account_id,
           e.two_factor_index,
           e.method,
           e.totp_secret_ciphertext,
           e.totp_secret_nonce,
           e.totp_secret_tag,
           e.totp_secret_version,
           e.totp_last_used_step
      from get_verified_totp_enrollment_for_account(p_accountId, p_now) e
     where e.totp_provider_type = 1;
$$;

create or replace function mark_password_reset_totp_step_used(
    p_accountId uuid,
    p_twoFactorIndex smallint,
    p_timeStep bigint)
returns table(
    result boolean,
    code text)
language sql
as $$
    select result,
           code
      from mark_totp_step_used(p_accountId, p_twoFactorIndex, p_timeStep);
$$;

create or replace function register_password_reset_request_rate_limit(
    p_rateLimitKey text,
    p_now timestamp with time zone,
    p_requestWindow interval,
    p_requestLimit integer,
    p_requestCooldown interval,
    p_blockPeriod interval)
returns table(
    result boolean,
    code text,
    request_count integer,
    blocked_until timestamp with time zone,
    retry_after_seconds integer)
language plpgsql
as $$
declare
    v_key text := nullif(btrim(p_rateLimitKey), '');
    v_now timestamp with time zone := coalesce(p_now, now());
    v_window interval := greatest(coalesce(p_requestWindow, interval '24 hours'), interval '1 second');
    v_limit integer := greatest(coalesce(p_requestLimit, 1), 1);
    v_cooldown interval := greatest(coalesce(p_requestCooldown, interval '0 seconds'), interval '0 seconds');
    v_block_period interval := greatest(coalesce(p_blockPeriod, interval '1 minute'), interval '1 second');
    v_row password_reset_rate_limits%rowtype;
    v_retry_at timestamp with time zone;
    v_retry_after_seconds integer;
    v_request_count integer;
begin
    if v_key is null then
        return query select false, 'PASSWORD_RESET_RATE_LIMIT_INVALID_KEY'::text, null::integer, null::timestamp with time zone, null::integer;
        return;
    end if;

    insert into password_reset_rate_limits(rate_limit_key, window_started_at, request_count, last_request_at, blocked_until)
    values(v_key, v_now, 0, null, null)
    on conflict (rate_limit_key) do nothing;

    select *
      into v_row
      from password_reset_rate_limits prrl
     where prrl.rate_limit_key = v_key
     for update;

    if v_row.blocked_until is not null and v_row.blocked_until > v_now then
        v_retry_after_seconds := ceiling(extract(epoch from (v_row.blocked_until - v_now)))::integer;
        return query select false, 'PASSWORD_RESET_RATE_LIMITED'::text, v_row.request_count, v_row.blocked_until, v_retry_after_seconds;
        return;
    end if;

    if v_row.window_started_at + v_window <= v_now then
        update password_reset_rate_limits prrl
           set window_started_at = v_now,
               request_count = 1,
               last_request_at = v_now,
               blocked_until = null
         where prrl.rate_limit_key = v_key;

        return query select true, 'PASSWORD_RESET_RATE_LIMIT_OK'::text, 1::integer, null::timestamp with time zone, 0::integer;
        return;
    end if;

    if v_row.last_request_at is not null
       and v_cooldown > interval '0 seconds'
       and v_row.last_request_at + v_cooldown > v_now then
        v_retry_at := v_row.last_request_at + v_cooldown;
        v_retry_after_seconds := ceiling(extract(epoch from (v_retry_at - v_now)))::integer;

        return query select false, 'PASSWORD_RESET_REQUEST_COOLDOWN'::text, v_row.request_count, v_retry_at, v_retry_after_seconds;
        return;
    end if;

    if v_row.request_count >= v_limit then
        update password_reset_rate_limits prrl
           set last_request_at = v_now,
               blocked_until = v_now + v_block_period
         where prrl.rate_limit_key = v_key
        returning prrl.blocked_until into v_retry_at;

        v_retry_after_seconds := ceiling(extract(epoch from (v_retry_at - v_now)))::integer;
        return query select false, 'PASSWORD_RESET_RATE_LIMITED'::text, v_row.request_count, v_retry_at, v_retry_after_seconds;
        return;
    end if;

    update password_reset_rate_limits prrl
       set request_count = prrl.request_count + 1,
           last_request_at = v_now,
           blocked_until = null
     where prrl.rate_limit_key = v_key
    returning prrl.request_count into v_request_count;

    return query select true, 'PASSWORD_RESET_RATE_LIMIT_OK'::text, v_request_count, null::timestamp with time zone, 0::integer;
end;
$$;

create or replace function cleanup_password_reset_rate_limits(
    p_now timestamp with time zone,
    p_retention interval)
returns table(
    result boolean,
    code text,
    deleted_count integer)
language plpgsql
as $$
declare
    v_now timestamp with time zone := coalesce(p_now, now());
    v_retention interval := greatest(coalesce(p_retention, interval '7 days'), interval '1 hour');
    v_deleted_count integer := 0;
begin
    delete from password_reset_rate_limits prrl
     where prrl.window_started_at < v_now - v_retention
       and (prrl.blocked_until is null or prrl.blocked_until < v_now);

    get diagnostics v_deleted_count = row_count;

    return query select true, 'PASSWORD_RESET_RATE_LIMIT_CLEANUP_COMPLETED'::text, v_deleted_count;
end;
$$;

create or replace function create_password_reset_request(
    p_passwordResetRequestId uuid,
    p_accountId uuid,
    p_method text,
    p_deliveryChannel text,
    p_keyCodeHash text,
    p_keyCodeHashVersion integer,
    p_destinationFingerprint text,
    p_destinationMasked text,
    p_requiresKeyCode boolean,
    p_requiresTotp boolean,
    p_expiresAt timestamp with time zone,
    p_maxAttempts integer,
    p_requestedByIp inet,
    p_requestedByUserAgent text,
    p_accountSecurityStampAtRequest uuid)
returns table(
    result boolean,
    code text,
    password_reset_request_id uuid,
    account_id uuid,
    expires_at timestamp with time zone)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    v_created_at timestamp with time zone := now();
    v_has_sms boolean := false;
    v_method text := lower(nullif(btrim(p_method), ''));
    v_delivery_channel text := lower(nullif(btrim(p_deliveryChannel), ''));
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, null::uuid, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if account_record.security_stamp is distinct from p_accountSecurityStampAtRequest then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    select exists(
        select 1
          from two_factor_authentications t
         where t.account_id = p_accountId
           and t.method = 2
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > v_created_at)
           and t.phone_number is not null
    ) into v_has_sms;

    if v_method is null then
        return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    if v_method = 'email' then
        if account_record.verify_status <> 1
           or v_delivery_channel <> 'email'
           or coalesce(p_requiresKeyCode, false) <> true
           or coalesce(p_requiresTotp, false) <> false
           or p_keyCodeHash is null
           or p_keyCodeHashVersion is null then
            return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
            return;
        end if;
    elsif v_method = 'sms' then
        if not v_has_sms
           or v_delivery_channel <> 'sms'
           or coalesce(p_requiresKeyCode, false) <> true
           or coalesce(p_requiresTotp, false) <> false
           or p_keyCodeHash is null
           or p_keyCodeHashVersion is null then
            return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
            return;
        end if;
    else
        return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    if p_expiresAt <= v_created_at then
        return query select false, 'PASSWORD_RESET_INVALID_EXPIRATION'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    if coalesce(p_maxAttempts, 0) <= 0 then
        return query select false, 'PASSWORD_RESET_INVALID_MAX_ATTEMPTS'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    update password_reset_requests pr
       set cancelled_at = v_created_at
     where pr.account_id = p_accountId
       and pr.consumed_at is null
       and pr.cancelled_at is null;

    insert into password_reset_requests(
        password_reset_request_id,
        account_id,
        method,
        delivery_channel,
        key_code_hash,
        key_code_hash_version,
        destination_fingerprint,
        destination_masked,
        requires_key_code,
        requires_totp,
        created_at,
        expires_at,
        max_attempts,
        requested_by_ip,
        requested_by_user_agent,
        account_security_stamp_at_request)
    values(
        p_passwordResetRequestId,
        p_accountId,
        v_method,
        v_delivery_channel,
        p_keyCodeHash,
        p_keyCodeHashVersion,
        p_destinationFingerprint,
        p_destinationMasked,
        coalesce(p_requiresKeyCode, true),
        coalesce(p_requiresTotp, false),
        v_created_at,
        p_expiresAt,
        p_maxAttempts,
        p_requestedByIp,
        p_requestedByUserAgent,
        p_accountSecurityStampAtRequest);

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, p_accountId, 'password_reset_requested', 'PASSWORD_RESET_REQUEST_CREATED', v_created_at);

    return query select true, 'PASSWORD_RESET_REQUEST_CREATED'::text, p_passwordResetRequestId, p_accountId, p_expiresAt;
end;
$$;

create or replace function cancel_password_reset_request(
    p_passwordResetRequestId uuid,
    p_cancelledAt timestamp with time zone,
    p_reasonCode text)
returns table(
    result boolean,
    code text,
    account_id uuid,
    cancelled_at timestamp with time zone)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_cancelled_at timestamp with time zone := coalesce(p_cancelledAt, now());
    v_reason_code text := coalesce(nullif(btrim(p_reasonCode), ''), 'PASSWORD_RESET_CANCELLED');
    v_event_type text := case
        when coalesce(nullif(btrim(p_reasonCode), ''), '') = 'PASSWORD_RESET_DELIVERY_FAILED' then 'password_reset_delivery_failed'
        else 'password_reset_cancelled'
    end;
begin
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.account_id, v_reset.consumed_at;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.account_id, v_reset.cancelled_at;
        return;
    end if;

    update password_reset_requests pr
       set cancelled_at = v_cancelled_at
     where pr.password_reset_request_id = p_passwordResetRequestId;

    update pending_password_reset_sessions pprs
       set revoked_at = v_cancelled_at,
           revoked_reason = v_reason_code
     where pprs.password_reset_request_id = p_passwordResetRequestId
       and pprs.revoked_at is null;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, v_reset.account_id, v_event_type, v_reason_code, v_cancelled_at);

    return query select true, v_reason_code, v_reset.account_id, v_cancelled_at;
end;
$$;

create or replace function get_pending_password_reset_session(
    p_resetAccessTokenHash text)
returns table(
    password_reset_request_id uuid,
    account_id uuid,
    reset_access_token_hash text,
    bootstrap_proof smallint,
    state smallint,
    available_configurations smallint[],
    selected_two_factor_configuration smallint,
    required_methods smallint[],
    completed_methods smallint[],
    current_expected_method smallint,
    challenge_code_hash text,
    challenge_expiration timestamp with time zone,
    challenge_attempts integer,
    challenge_resends integer,
    next_challenge_allowed_at timestamp with time zone,
    created_on timestamp with time zone,
    expires_at timestamp with time zone,
    selected_at timestamp with time zone,
    two_factor_completed_at timestamp with time zone,
    password_changed_at timestamp with time zone)
language sql
stable
as $$
    select p.password_reset_request_id,
           p.account_id,
           p.reset_access_token_hash,
           p.bootstrap_proof,
           p.state,
           p.available_configurations,
           p.selected_two_factor_configuration,
           p.required_methods,
           p.completed_methods,
           p.current_expected_method,
           p.challenge_code_hash,
           p.challenge_expiration,
           p.challenge_attempts,
           p.challenge_resends,
           p.next_challenge_allowed_at,
           p.created_on,
           p.expires_at,
           p.selected_at,
           p.two_factor_completed_at,
           p.password_changed_at
      from pending_password_reset_sessions p
     where p.reset_access_token_hash = p_resetAccessTokenHash
       and p.revoked_at is null
     limit 1;
$$;

create or replace function upsert_pending_password_reset_session(
    p_resetAccessTokenHash text,
    p_passwordResetRequestId uuid,
    p_accountId uuid,
    p_bootstrapProof smallint,
    p_state smallint,
    p_availableConfigurations smallint[],
    p_selectedTwoFactorConfiguration smallint,
    p_requiredMethods smallint[],
    p_completedMethods smallint[],
    p_currentExpectedMethod smallint,
    p_challengeCodeHash text,
    p_challengeExpiration timestamp with time zone,
    p_challengeAttempts integer,
    p_challengeResends integer,
    p_nextChallengeAllowedAt timestamp with time zone,
    p_createdOn timestamp with time zone,
    p_expiresAt timestamp with time zone,
    p_selectedAt timestamp with time zone,
    p_twoFactorCompletedAt timestamp with time zone,
    p_passwordChangedAt timestamp with time zone)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_created_on timestamp with time zone := coalesce(p_createdOn, now());
    v_available_configurations smallint[] := coalesce(p_availableConfigurations, array[]::smallint[]);
    v_required_methods smallint[] := coalesce(p_requiredMethods, array[]::smallint[]);
    v_completed_methods smallint[] := coalesce(p_completedMethods, array[]::smallint[]);
begin
    if nullif(btrim(coalesce(p_resetAccessTokenHash, '')), '') is null then
        return query select false, 'PASSWORD_RESET_SESSION_HASH_REQUIRED'::text;
        return;
    end if;

    if p_accountId is null then
        return query select false, 'PASSWORD_RESET_SESSION_ACCOUNT_REQUIRED'::text;
        return;
    end if;

    if p_expiresAt is null or p_expiresAt <= v_created_on then
        return query select false, 'PASSWORD_RESET_SESSION_INVALID_EXPIRATION'::text;
        return;
    end if;

    if p_passwordResetRequestId is not null then
        select *
          into v_reset
          from password_reset_requests pr
         where pr.password_reset_request_id = p_passwordResetRequestId
         for update;

        if not found then
            return query select false, 'PASSWORD_RESET_NOT_FOUND'::text;
            return;
        end if;

        if v_reset.account_id is distinct from p_accountId then
            return query select false, 'PASSWORD_RESET_ACCOUNT_MISMATCH'::text;
            return;
        end if;

        if v_reset.consumed_at is not null then
            return query select false, 'PASSWORD_RESET_CONSUMED'::text;
            return;
        end if;

        if v_reset.cancelled_at is not null then
            return query select false, 'PASSWORD_RESET_CANCELLED'::text;
            return;
        end if;

        if v_reset.expires_at <= now() then
            return query select false, 'PASSWORD_RESET_EXPIRED'::text;
            return;
        end if;
    end if;

    insert into pending_password_reset_sessions(
        reset_access_token_hash,
        password_reset_request_id,
        account_id,
        bootstrap_proof,
        state,
        available_configurations,
        selected_two_factor_configuration,
        required_methods,
        completed_methods,
        current_expected_method,
        challenge_code_hash,
        challenge_expiration,
        challenge_attempts,
        challenge_resends,
        next_challenge_allowed_at,
        created_on,
        expires_at,
        selected_at,
        two_factor_completed_at,
        password_changed_at,
        revoked_at,
        revoked_reason)
    values(
        p_resetAccessTokenHash,
        p_passwordResetRequestId,
        p_accountId,
        p_bootstrapProof,
        p_state,
        v_available_configurations,
        p_selectedTwoFactorConfiguration,
        v_required_methods,
        v_completed_methods,
        p_currentExpectedMethod,
        p_challengeCodeHash,
        p_challengeExpiration,
        coalesce(p_challengeAttempts, 0),
        coalesce(p_challengeResends, 0),
        p_nextChallengeAllowedAt,
        v_created_on,
        p_expiresAt,
        p_selectedAt,
        p_twoFactorCompletedAt,
        p_passwordChangedAt,
        null,
        null)
    on conflict(reset_access_token_hash) do update
       set password_reset_request_id = excluded.password_reset_request_id,
           account_id = excluded.account_id,
           bootstrap_proof = excluded.bootstrap_proof,
           state = excluded.state,
           available_configurations = excluded.available_configurations,
           selected_two_factor_configuration = excluded.selected_two_factor_configuration,
           required_methods = excluded.required_methods,
           completed_methods = excluded.completed_methods,
           current_expected_method = excluded.current_expected_method,
           challenge_code_hash = excluded.challenge_code_hash,
           challenge_expiration = excluded.challenge_expiration,
           challenge_attempts = excluded.challenge_attempts,
           challenge_resends = excluded.challenge_resends,
           next_challenge_allowed_at = excluded.next_challenge_allowed_at,
           created_on = excluded.created_on,
           expires_at = excluded.expires_at,
           selected_at = excluded.selected_at,
           two_factor_completed_at = excluded.two_factor_completed_at,
           password_changed_at = excluded.password_changed_at,
           revoked_at = null,
           revoked_reason = null;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, p_accountId, 'password_reset_session_saved', 'PASSWORD_RESET_SESSION_SAVED', now());

    return query select true, 'PASSWORD_RESET_SESSION_SAVED'::text;
end;
$$;

create or replace function revoke_pending_password_reset_session(
    p_resetAccessTokenHash text,
    p_revokedAt timestamp with time zone,
    p_reasonCode text)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    v_revoked_at timestamp with time zone := coalesce(p_revokedAt, now());
    v_reason_code text := coalesce(nullif(btrim(p_reasonCode), ''), 'PASSWORD_RESET_SESSION_REVOKED');
    v_account_id uuid;
    v_password_reset_request_id uuid;
begin
    update pending_password_reset_sessions p
       set revoked_at = v_revoked_at,
           revoked_reason = v_reason_code
     where p.reset_access_token_hash = p_resetAccessTokenHash
       and p.revoked_at is null
     returning p.account_id, p.password_reset_request_id
      into v_account_id, v_password_reset_request_id;

    if not found then
        return query select true, 'PASSWORD_RESET_SESSION_NOT_FOUND'::text;
        return;
    end if;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(v_password_reset_request_id, v_account_id, 'password_reset_session_revoked', v_reason_code, v_revoked_at);

    return query select true, v_reason_code;
end;
$$;

create or replace function revoke_pending_password_reset_sessions_for_account(
    p_accountId uuid,
    p_revokedAt timestamp with time zone,
    p_reasonCode text)
returns table(result boolean, code text, revoked_count integer)
language plpgsql
as $$
declare
    v_revoked_at timestamp with time zone := coalesce(p_revokedAt, now());
    v_reason_code text := coalesce(nullif(btrim(p_reasonCode), ''), 'PASSWORD_RESET_SESSION_REVOKED');
    v_revoked_count integer := 0;
begin
    if p_accountId is null then
        return query select false, 'PASSWORD_RESET_SESSION_ACCOUNT_REQUIRED'::text, 0;
        return;
    end if;

    with revoked as (
        update pending_password_reset_sessions p
           set revoked_at = v_revoked_at,
               revoked_reason = v_reason_code
         where p.account_id = p_accountId
           and p.revoked_at is null
         returning p.password_reset_request_id, p.account_id
    ), inserted_events as (
        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        select r.password_reset_request_id,
               r.account_id,
               'password_reset_session_revoked',
               v_reason_code,
               v_revoked_at
          from revoked r
        returning 1
    )
    select count(*)
      into v_revoked_count
      from inserted_events;

    if v_revoked_count = 0 then
        return query select true, 'PASSWORD_RESET_SESSION_NOT_FOUND'::text, 0;
        return;
    end if;

    return query select true, v_reason_code, v_revoked_count;
end;
$$;

create or replace function get_password_reset_request_for_finalize(
    p_passwordResetRequestId uuid)
returns table(
    result boolean,
    code text,
    password_reset_request_id uuid,
    account_id uuid,
    method text,
    delivery_channel text,
    key_code_hash text,
    key_code_hash_version integer,
    requires_key_code boolean,
    requires_totp boolean,
    expires_at timestamp with time zone,
    consumed_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    attempt_count integer,
    max_attempts integer,
    account_security_stamp_at_request uuid,
    email_verified boolean,
    sms_verified boolean,
    authenticator_verified boolean,
    current_email_address text,
    current_phone_number text,
    current_phone_country_code text)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_email_address text;
    v_phone_number text;
    v_phone_country_code text;
    v_email_verified boolean := false;
    v_sms_verified boolean := false;
    v_authenticator_verified boolean := false;
begin
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
     limit 1;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::uuid, null::text, null::text, null::text, null::integer, null::boolean, null::boolean, null::timestamp with time zone, null::timestamp with time zone, null::timestamp with time zone, null::integer, null::integer, null::uuid, false, false, false, null::text, null::text, null::text;
        return;
    end if;

    select a.email_address,
           a.verify_status = 1
      into v_email_address,
           v_email_verified
      from accounts a
     where a.account_id = v_reset.account_id;

    select t.phone_number, t.phone_country_code
      into v_phone_number, v_phone_country_code
      from two_factor_authentications t
     where t.account_id = v_reset.account_id
       and t.method = 2
       and t.verified = true
       and t.revoked_at is null
       and t.phone_number is not null
       and (t.expiration is null or t.expiration > now())
     order by t.required desc, t.priority asc, t.two_factor_index asc
     limit 1;

    v_sms_verified := v_phone_number is not null;

    v_authenticator_verified := exists(
        select 1
          from two_factor_authentications t
         where t.account_id = v_reset.account_id
           and t.method = 3
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > now())
           and t.totp_provider_type = 1
           and t.totp_secret_ciphertext is not null
           and octet_length(t.totp_secret_ciphertext) > 0
           and t.totp_secret_nonce is not null
           and octet_length(t.totp_secret_nonce) > 0
           and t.totp_secret_tag is not null
           and octet_length(t.totp_secret_tag) > 0
           and coalesce(t.totp_secret_version, 0) > 0
    );

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
        return;
    end if;

    if v_reset.expires_at <= now() then
        return query select false, 'PASSWORD_RESET_EXPIRED'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
        return;
    end if;

    return query select true, 'PASSWORD_RESET_READY'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
end;
$$;

create or replace function register_password_reset_failed_attempt(
    p_passwordResetRequestId uuid,
    p_failedAt timestamp with time zone)
returns table(
    result boolean,
    code text,
    account_id uuid,
    attempt_count integer,
    max_attempts integer,
    cancelled_at timestamp with time zone)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_failed_at timestamp with time zone := coalesce(p_failedAt, now());
    v_attempt_count integer;
    v_cancelled_at timestamp with time zone;
begin
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::integer, null::integer, null::timestamp with time zone;
        return;
    end if;

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.account_id, v_reset.attempt_count, v_reset.max_attempts, v_reset.cancelled_at;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.account_id, v_reset.attempt_count, v_reset.max_attempts, v_reset.cancelled_at;
        return;
    end if;

    if v_reset.expires_at <= v_failed_at then
        update password_reset_requests pr
           set cancelled_at = v_failed_at
         where pr.password_reset_request_id = p_passwordResetRequestId
           and pr.cancelled_at is null;

        update pending_password_reset_sessions pprs
           set revoked_at = v_failed_at,
               revoked_reason = 'PASSWORD_RESET_EXPIRED'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_expired', 'PASSWORD_RESET_EXPIRED', v_failed_at);

        return query select false, 'PASSWORD_RESET_EXPIRED'::text, v_reset.account_id, v_reset.attempt_count, v_reset.max_attempts, v_failed_at;
        return;
    end if;

    v_attempt_count := v_reset.attempt_count + 1;

    if v_attempt_count >= v_reset.max_attempts then
        update password_reset_requests pr
           set attempt_count = v_attempt_count,
               cancelled_at = v_failed_at
         where pr.password_reset_request_id = p_passwordResetRequestId
        returning pr.cancelled_at into v_cancelled_at;

        update pending_password_reset_sessions pprs
           set revoked_at = v_failed_at,
               revoked_reason = 'PASSWORD_RESET_ATTEMPTS_EXCEEDED'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_attempts_exceeded', 'PASSWORD_RESET_ATTEMPTS_EXCEEDED', v_failed_at);

        return query select false, 'PASSWORD_RESET_ATTEMPTS_EXCEEDED'::text, v_reset.account_id, v_attempt_count, v_reset.max_attempts, v_cancelled_at;
        return;
    end if;

    update password_reset_requests pr
       set attempt_count = v_attempt_count
     where pr.password_reset_request_id = p_passwordResetRequestId;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_failed_attempt', 'PASSWORD_RESET_ATTEMPT_RECORDED', v_failed_at);

    return query select true, 'PASSWORD_RESET_ATTEMPT_RECORDED'::text, v_reset.account_id, v_attempt_count, v_reset.max_attempts, null::timestamp with time zone;
end;
$$;

create or replace function promote_password_reset(
    p_passwordResetRequestId uuid,
    p_accountId uuid,
    p_hashedPassword bytea,
    p_saltOne bytea,
    p_siv bytea,
    p_nonce bytea,
    p_newSecurityStamp uuid,
    p_promotedAt timestamp with time zone)
returns table(
    result boolean,
    code text,
    account_id uuid,
    account_security_stamp uuid,
    consumed_at timestamp with time zone)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_current_security_stamp uuid;
    v_promoted_at timestamp with time zone := coalesce(p_promotedAt, now());
begin
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::uuid, null::timestamp with time zone;
        return;
    end if;

    -- The application host and database can differ by a small clock skew in
    -- host-backed system tests and real deployments. Clamp the supplied
    -- promotion timestamp to the reset row creation time so consuming the
    -- artifact never violates ck_password_reset_consumed_after_created.
    v_promoted_at := greatest(v_promoted_at, v_reset.created_at);

    if v_reset.account_id is distinct from p_accountId then
        return query select false, 'PASSWORD_RESET_ACCOUNT_MISMATCH'::text, v_reset.account_id, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.account_id, null::uuid, v_reset.consumed_at;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.account_id, null::uuid, v_reset.cancelled_at;
        return;
    end if;

    if v_reset.expires_at <= v_promoted_at then
        update password_reset_requests pr
           set cancelled_at = v_promoted_at
         where pr.password_reset_request_id = p_passwordResetRequestId
           and pr.cancelled_at is null;

        update pending_password_reset_sessions pprs
           set revoked_at = v_promoted_at,
               revoked_reason = 'PASSWORD_RESET_EXPIRED'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_expired', 'PASSWORD_RESET_EXPIRED', v_promoted_at);

        return query select false, 'PASSWORD_RESET_EXPIRED'::text, v_reset.account_id, null::uuid, v_promoted_at;
        return;
    end if;

    select a.security_stamp
      into v_current_security_stamp
      from accounts a
     where a.account_id = p_accountId
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, v_reset.account_id, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if v_current_security_stamp is distinct from v_reset.account_security_stamp_at_request then
        update password_reset_requests pr
           set cancelled_at = v_promoted_at
         where pr.password_reset_request_id = p_passwordResetRequestId
           and pr.cancelled_at is null;

        update pending_password_reset_sessions pprs
           set revoked_at = v_promoted_at,
               revoked_reason = 'PASSWORD_RESET_ACCOUNT_STALE'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_stale_account', 'PASSWORD_RESET_ACCOUNT_STALE', v_promoted_at);

        return query select false, 'PASSWORD_RESET_ACCOUNT_STALE'::text, v_reset.account_id, v_current_security_stamp, v_promoted_at;
        return;
    end if;

    update accounts a
       set hashed_password = p_hashedPassword,
           salt_one = p_saltOne,
           siv = p_siv,
           nonce = p_nonce,
           security_stamp = p_newSecurityStamp,
           login_failures = 0
     where a.account_id = p_accountId;

    update sessions s
       set cut_off = case
               when s.cut_off is null then v_promoted_at
               when s.cut_off > v_promoted_at then v_promoted_at
               else s.cut_off
           end
     where s.account_id = p_accountId;

    update password_reset_requests pr
       set consumed_at = v_promoted_at
     where pr.password_reset_request_id = p_passwordResetRequestId;

    update pending_password_reset_sessions pprs
       set state = 8,
           password_changed_at = v_promoted_at,
           revoked_at = v_promoted_at,
           revoked_reason = 'PASSWORD_RESET_COMPLETED'
     where pprs.account_id = p_accountId
       and pprs.revoked_at is null;

    update password_reset_requests pr
       set cancelled_at = v_promoted_at
     where pr.account_id = p_accountId
       and pr.password_reset_request_id <> p_passwordResetRequestId
       and pr.consumed_at is null
       and pr.cancelled_at is null;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, p_accountId, 'password_reset_completed', 'PASSWORD_RESET_COMPLETED', v_promoted_at);

    return query select true, 'PASSWORD_RESET_COMPLETED'::text, p_accountId, p_newSecurityStamp, v_promoted_at;
end;
$$;

create or replace function cleanup_expired_password_reset_requests(
    p_now timestamp with time zone,
    p_retention interval)
returns table(
    result boolean,
    code text,
    cancelled_count integer,
    deleted_count integer)
language plpgsql
as $$
declare
    v_now timestamp with time zone := coalesce(p_now, now());
    v_retention interval := greatest(coalesce(p_retention, interval '30 days'), interval '1 day');
    v_cancelled_count integer := 0;
    v_deleted_count integer := 0;
begin
    update password_reset_requests pr
       set cancelled_at = v_now
     where pr.expires_at <= v_now
       and pr.consumed_at is null
       and pr.cancelled_at is null;

    get diagnostics v_cancelled_count = row_count;

    update pending_password_reset_sessions pprs
       set revoked_at = v_now,
           revoked_reason = 'PASSWORD_RESET_EXPIRED'
      from password_reset_requests pr
     where pprs.password_reset_request_id = pr.password_reset_request_id
       and pr.cancelled_at = v_now
       and pprs.revoked_at is null;

    delete from password_reset_requests pr
     where coalesce(pr.consumed_at, pr.cancelled_at) is not null
       and coalesce(pr.consumed_at, pr.cancelled_at) < v_now - v_retention;

    get diagnostics v_deleted_count = row_count;

    return query select true, 'PASSWORD_RESET_CLEANUP_COMPLETED'::text, v_cancelled_count, v_deleted_count;
end;
$$;


create or replace function place_activation(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_emailAddress text,
    p_code text,
    p_createdOn timestamp with time zone,
    p_term smallint,
    p_interval smallint,
    p_closeOff timestamp with time zone,
    p_featureSet smallint,
    p_platformBacker smallint,
    p_platformText text,
    p_status smallint,
    p_delayedStart interval)
returns table(result boolean, code text, status smallint)
language plpgsql
as $$
declare
    v_term_interval interval;
begin
    if not exists (
        select 1
          from accounts
         where account_id = p_accountId) then
        return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint;
        return;
    end if;

    if not exists (
        select 1
          from accounts
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp) then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::smallint;
        return;
    end if;

    if not exists (
        select 1
          from accounts
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp
           and lower(email_address) = lower(p_emailAddress)) then
        return query select false, 'ACTIVATION_EMAIL_MISMATCH'::text, null::smallint;
        return;
    end if;

    if p_code is null or btrim(p_code) = '' then
        return query select false, 'ACTIVATION_INVALID'::text, null::smallint;
        return;
    end if;

    if p_term is null or p_term < 1 or p_term > 11 then
        return query select false, 'ACTIVATION_INVALID_TERM'::text, null::smallint;
        return;
    end if;

    if p_interval is null or p_interval < 0 or p_interval > 10 then
        return query select false, 'ACTIVATION_INVALID_RECYCLE'::text, null::smallint;
        return;
    end if;

    v_term_interval := case p_term
        when 1 then interval '1 day'
        when 2 then interval '1 week'
        when 3 then interval '2 weeks'
        when 4 then interval '1 month'
        when 5 then interval '1 month'
        when 6 then interval '1 month'
        when 7 then interval '3 months'
        when 8 then interval '6 months'
        when 9 then interval '9 months'
        when 10 then interval '1 year'
        when 11 then interval '100 years'
    end;

    insert into activations(
        account_id,
        created_on,
        term,
        off_at,
        feature_set,
        code,
        status,
        day_duration,
        duration_repeat,
        platform_backer,
        platform_text,
        delayed_start)
    values(
        p_accountId,
        p_createdOn,
        v_term_interval,
        p_closeOff,
        p_featureSet,
        p_code,
        p_status,
        p_term,
        p_interval,
        p_platformBacker,
        p_platformText,
        case when p_delayedStart is null then null else p_createdOn + p_delayedStart end);

    return query select true, 'ACTIVATION_STORED'::text, p_status;
exception
    when unique_violation then
        return query select false, 'ACTIVATION_CONFLICT'::text, null::smallint;
end;
$$;

create or replace function cancel_activation_request(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_code text,
    p_cancelledOn timestamp with time zone)
returns table(result boolean, code text, status smallint)
language plpgsql
as $$
begin
    if not exists (
        select 1
          from accounts
         where account_id = p_accountId) then
        return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint;
        return;
    end if;

    if not exists (
        select 1
          from accounts
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp) then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::smallint;
        return;
    end if;

    update activations a
       set status = 5,
           off_at = least(a.off_at, p_cancelledOn)
     where a.account_id = p_accountId
       and a.code = p_code
       and a.status = 3;

    if not found then
        return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint;
        return;
    end if;

    return query select true, 'ACTIVATION_CANCELLED'::text, 5::smallint;
end;
$$;

create or replace function disable_activation(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_emailAddress text,
    p_createdOn timestamp with time zone,
    p_closeOff timestamp with time zone,
    p_status smallint)
returns table(result boolean, code text, status smallint)
language plpgsql
as $$
begin
    if not exists (
        select 1
          from accounts
         where account_id = p_accountId) then
        return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint;
        return;
    end if;

    if not exists (
        select 1
          from accounts
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp) then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::smallint;
        return;
    end if;

    if not exists (
        select 1
          from accounts
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp
           and lower(email_address) = lower(p_emailAddress)) then
        return query select false, 'ACTIVATION_EMAIL_MISMATCH'::text, null::smallint;
        return;
    end if;

    update activations a
       set status = p_status,
           off_at = least(a.off_at, p_closeOff)
     where a.account_id = p_accountId
       and a.created_on <= p_createdOn
       and a.off_at >= p_createdOn
       and a.status in (1, 3);

    if found then
        return query select true, 'ACTIVATION_DISABLED'::text, p_status;
        return;
    end if;

    if exists (
        select 1
          from activations
         where account_id = p_accountId
           and created_on <= p_createdOn
           and off_at < p_createdOn
           and status in (1, 3)) then
        update activations a
           set status = 5
         where a.account_id = p_accountId
           and a.created_on <= p_createdOn
           and a.off_at < p_createdOn
           and a.status in (1, 3);

        return query select false, 'ACTIVATION_EXPIRED'::text, null::smallint;
        return;
    end if;

    return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint;
end;
$$;

create or replace function verify_activation(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_emailAddress text,
    p_code text,
    p_createdOn timestamp with time zone,
    p_position smallint,
    p_upperLimit smallint)
returns table(
    result boolean,
    code text,
    feature_set smallint,
    off_at timestamp with time zone,
    day_duration smallint,
    duration_repeat smallint)
language plpgsql
as $$
declare
    v_activation_id bigint;
    v_feature_set smallint;
    v_off_at timestamp with time zone;
    v_day_duration smallint;
    v_duration_repeat smallint;
begin
    if not exists (
        select 1
          from accounts
         where account_id = p_accountId) then
        return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
        return;
    end if;

    if not exists (
        select 1
          from accounts
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp) then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
        return;
    end if;

    if not exists (
        select 1
          from accounts
         where account_id = p_accountId
           and security_stamp = p_accountSecurityStamp
           and lower(email_address) = lower(p_emailAddress)) then
        return query select false, 'ACTIVATION_EMAIL_MISMATCH'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
        return;
    end if;

    if p_code is null or btrim(p_code) = '' then
        return query select false, 'ACTIVATION_CODE_MISMATCH'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
        return;
    end if;

    if greatest(coalesce(p_upperLimit, 1), 0) = 0 then
        return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
        return;
    end if;

    select a.activation_id,
           a.feature_set,
           a.off_at,
           a.day_duration,
           a.duration_repeat
      into v_activation_id,
           v_feature_set,
           v_off_at,
           v_day_duration,
           v_duration_repeat
      from activations a
     where a.account_id = p_accountId
       and a.code = p_code
       and a.created_on <= p_createdOn
       and a.off_at >= p_createdOn
       and a.status in (1, 3)
     order by a.created_on desc,
              a.activation_id desc
     offset greatest(coalesce(p_position, 0), 0)
     limit 1;

    if v_activation_id is null then
        if exists (
            select 1
              from activations a
             where a.account_id = p_accountId
               and a.code = p_code
               and a.created_on <= p_createdOn
               and a.off_at < p_createdOn
               and a.status in (1, 3)) then
            update activations a
               set status = 5
             where a.account_id = p_accountId
               and a.code = p_code
               and a.created_on <= p_createdOn
               and a.off_at < p_createdOn
               and a.status in (1, 3);

            return query select false, 'ACTIVATION_EXPIRED'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
            return;
        end if;

        if exists (
            select 1
              from activations a
             where a.account_id = p_accountId
               and a.code = p_code) then
            return query select false, 'ACTIVATION_NOT_FOUND'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
            return;
        end if;

        return query select false, 'ACTIVATION_CODE_MISMATCH'::text, null::smallint, null::timestamp with time zone, null::smallint, null::smallint;
        return;
    end if;

    update activations a
       set status = 4
     where a.activation_id = v_activation_id;

    return query
    select true,
           'ACTIVATION_VERIFIED'::text,
           v_feature_set,
           v_off_at,
           v_day_duration,
           v_duration_repeat;
end;
$$;


create table if not exists system_test_delivery_messages(
    delivery_id uuid primary key,
    created_at timestamptz not null default now(),
    channel text not null,
    purpose text not null,
    destination text not null,
    subject text null,
    body text not null,
    code text null,
    correlation_id text null
);

create index if not exists ix_system_test_delivery_messages_lookup
    on system_test_delivery_messages(channel, purpose, destination, created_at desc);

