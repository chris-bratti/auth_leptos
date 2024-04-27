-- Your SQL goes here
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    first_name text NOT NULL,
    last_name text NOT NULL,
    username text NOT NULL,
    pass_hash text NOT NULL,
    reset_link text,
    reset_link_expiration TIMESTAMP,
    active_sessions text[]
)