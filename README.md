# Leptos Auth
## A full stack user authentication application written in pure Rust

## Features:
### Security
- Secure password & reset token hashing with Argon2
- Secure email encryption with AES256-GCM
- User verification through securely generated email links
- Verification & password reset tokens expire after 20 minutes
- User-only pages - ensures only logged in and verified users can access certain pages
- SMTP via TLS

### User friendly
- Easy to navigate UI built with Leptos
- Password reset capabilities - generates a secure reset token sent to user's email
- Session storage using Actix Web & Redis - user's sessions are persisted to avoid needless re-authentication

### Persistent storage
- User data persisted with Postgres DB
- Full CRUD operations built with Diesel
- Database initialization and migrations supported via Diesel

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

Still a work in progress!
