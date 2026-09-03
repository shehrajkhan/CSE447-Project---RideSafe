-- RideSafe database schema for Supabase (Postgres)
-- Run this in the Supabase SQL editor to set up all tables.
--
-- IMPORTANT: every "encrypted" column below stores ciphertext + MAC tag
-- as JSON (jsonb), matching the shared crypto contract in crypto/__init__.py:
--   {"scheme": "ecies"|"rsa", "ciphertext": "...", "ephemeral_pubkey": "...", "mac": "..."}
-- No plaintext sensitive data is ever written to these columns.

-- ---------------------------------------------------------------------
-- Users: riders, drivers, admins
-- ---------------------------------------------------------------------
create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    username text unique not null,
    password_hash text not null,        -- your own salted-hash output, not plaintext
    password_salt text not null,        -- store salt separately if your scheme needs it
    role text not null check (role in ('rider', 'driver', 'admin')),

    email_encrypted jsonb not null,     -- RSA-encrypted, {ciphertext, mac, ...}
    contact_encrypted jsonb not null,   -- RSA-encrypted

    otp_secret text,                    -- HOTP/TOTP secret (Teammate C)
    status text not null default 'active' check (status in ('active', 'suspended')),

    created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Keys: each user's RSA + ECC keypairs (Key Management Module)
-- ---------------------------------------------------------------------
create table if not exists user_keys (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,

    rsa_public_key text not null,
    rsa_private_key_encrypted jsonb not null,   -- wrapped with a key derived from the user's password

    ecc_public_key text not null,
    ecc_private_key_encrypted jsonb not null,

    rotated_at timestamptz not null default now(),
    created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Profiles: name/phone/address/vehicle info (RSA-encrypted, "profile" data)
-- ---------------------------------------------------------------------
create table if not exists profiles (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,

    name_encrypted jsonb,
    phone_encrypted jsonb,
    address_encrypted jsonb,
    vehicle_info_encrypted jsonb,   -- drivers only, nullable for riders

    updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Trips: ride requests & trip logs (ECC-encrypted, "posts" data)
-- ---------------------------------------------------------------------
create table if not exists trips (
    id uuid primary key default gen_random_uuid(),
    rider_id uuid not null references users(id),
    driver_id uuid references users(id),   -- null until a driver accepts

    pickup_encrypted jsonb not null,       -- ECC-encrypted {ciphertext, ephemeral_pubkey, mac}
    dropoff_encrypted jsonb not null,
    timing_encrypted jsonb not null,

    status text not null default 'requested'
        check (status in ('requested', 'accepted', 'in_progress', 'completed', 'cancelled')),

    created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Chat messages: rider <-> driver, tied to a trip
-- ---------------------------------------------------------------------
create table if not exists chat_messages (
    id uuid primary key default gen_random_uuid(),
    trip_id uuid not null references trips(id) on delete cascade,
    sender_id uuid not null references users(id),

    message_encrypted jsonb not null,   -- ECC-encrypted {ciphertext, ephemeral_pubkey, mac}

    sent_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Sessions: active login sessions (token-based, random + unpredictable)
-- ---------------------------------------------------------------------
create table if not exists sessions (
    token text primary key,             -- e.g. secrets.token_hex(32)
    user_id uuid not null references users(id) on delete cascade,

    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked boolean not null default false
);

-- Helpful indexes
create index if not exists idx_trips_rider on trips(rider_id);
create index if not exists idx_trips_driver on trips(driver_id);
create index if not exists idx_chat_trip on chat_messages(trip_id);
create index if not exists idx_sessions_user on sessions(user_id);
