# Leptos Auth
## A full stack user authentication application written in pure Rust

## Features:
### Security
- Secure password & reset token hashing with Argon2
- Secure email encryption with AES256-GCM
- Two factor authentication with Time-Based One Time Passwords (TOTP)
- Password retry limits - lock accounts after too many failed tries
- User verification through securely generated email links
- Verification & password reset tokens expire after 20 minutes
- User-only pages - ensure only authenticated users can access sensitive pages
- SMTP via TLS

### User friendly
- Easy to navigate UI built with Leptos
- Easy two factor authentication enrollment with QR code based secrets
- Password reset capabilities - generates a secure reset token sent to user's email
- Persistent session storage using Actix Web & Redis - user's sessions are saved with persistent session cookies to avoid repeated authentication

### Persistent storage
- User data persisted with Postgres DB
- Full CRUD operations built with Diesel
- Database initialization and migrations supported via Diesel
- Automated DB bootstrapping - `init-db.sh` and `init.sql` files automate database, user, and table creation!

## Dockerized!

This project can be run in a docker container! And it has everything you need to connect and bootstrap your postgres database.

The recommended `docker-compose.yml` file can be downloaded by running:

```
$ wget https://raw.githubusercontent.com/rhysbratti/auth_leptos/master/docker-compose.yml
```
You will need to supply a few secrets in an `.env` file. I've included a template in this repo, `example.env`. You can download it by running:

```
$ wget https://raw.githubusercontent.com/rhysbratti/auth_leptos/master/example.env

$ mv example.env .env
```

And then updating the values for your app:

- `FROM_EMAIL`: SMTP address for sending emails to users
- `SMTP_KEY`: Password for SMTP account
- `TWO_FACTOR_KEY`: 32 character encryption key for encrypting user TOTP keys
- `SMTP_ENCRYPTION_KEY`: 32 character encryption key for encrypting user emails
- `LOG_KEY`: 32 character encryption key for encrypting sensitive data in the application logs
- `MASTER_USER`: Master username for postgres DB
- `MASTER_PASSWORD`: Master password for postgres DB
- `AUTH_LEPTOS_URL`: Base URL for your application, used in password reset and user verification links that are emailed to users. Set this to `http://localhost:3000` for local testing.

As noted above, **all encryption keys need to be 32 characters long**. Generate these strings with whatever method you'd like, ex:

```
$ cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
```

After running `docker-compose up -d`, you should have the following containers:

1. `leptos-auth` - The container for the Leptos application
2. `leptos_postgres` - The postgres container for your database
3. `redis-cache` - The Redis cache for session storage

## Forking and Contributions

The purpose of `auth_leptos` is to serve as a polished(ish) template for full stack Rust applications with simple yet secure user authentication. 

### Using this code

**Feel free to fork, copy, implement, and otherwise plunder what you need from this repo**. I created this repo for a few simple reasons:

- To get more personal experience with full-stack development (being a mainly back-end dev)
- To get more experience with Rust
- To get more experience with secure user authentication
- To build an extendable base for my future web-apps, where I don't have to worry about re-implementing user authentication
- To provide an end-to-end example of authentication and user sessions with the Leptos framework

Leptos is a great framework - but its also a bit new. I had a hard time finding implementation examples, so I wanted to put one out there for anybody looking to build web-applications with Rust!

If you are feeling particularly gracious, drop me a credit in your projects:

```
// Code adapted from auth_leptos by Chris Bratti
// Repository: https://github.com/chris-bratti/auth_leptos
```

### Contributions

**This repo is open to contributions** - feel free to open a PR for any changes, updates, or refactors as you see fit. I am *quite* open to feedback on this project - if you have some good ideas I would love to see them :)


## Libraries, Frameworks, and Technologies
### A list of the libraries and frameworks used in this project
- [Leptos](https://github.com/leptos-rs/leptos) - a full-stack, isomorphic Rust web framework leveraging fine-grained reactivity to build declarative user interfaces
- [Actix Web](https://github.com/actix/actix-web) (via Leptos integration) - a powerful, pragmatic, and extremely fast web framework for Rust
- [Diesel](https://github.com/diesel-rs/diesel) - a safe, extensible ORM and Query Builder for Rust
- [PostgreSQL](https://www.postgresql.org/) - a powerful, open source object-relational database system 
- [Redis](https://github.com/redis/redis) - a key-value based in-memory database
- [Lettre](https://github.com/lettre/lettre) - a mailer library for Rust
- [Maud](https://github.com/lambda-fairy/maud) - an HTML template engine for Rust
- [RustCrypt Argon2](https://docs.rs/argon2/latest/argon2/) - a Pure Rust implementation of the Argon2 password hashing function.
- [totp-rs](https://github.com/constantoine/totp-rs) - RFC-compliant TOTP implementation with QR code generation

