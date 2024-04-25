-- Your SQL goes here
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    first_name text NOT NULL,
    last_name text NOT NULL,
    username text NOT NULL,
    pass_hash text NOT NULL,
    active_sessions text[]
)