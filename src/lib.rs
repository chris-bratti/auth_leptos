use core::fmt;

use serde::{Deserialize, Serialize};
#[cfg(feature = "ssr")]
use thiserror::Error;

pub mod app;
pub use app::*;
pub mod auth;
pub mod client;
pub use client::*;
#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub mod server;
pub mod smtp;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use app::*;
    use leptos::*;

    console_error_panic_hook::set_once();

    mount_to_body(App);
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
    verified: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AuthError {
    InvalidCredentials,
    InternalServerError(String),
    InvalidToken,
    PasswordConfirmationError,
    InvalidPassword,
    Error(String),
    TOTPError,
    AccountLocked,
}

// Implement std::fmt::Display for AppError
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => {
                write!(f, "Invalid username or password")
            }
            AuthError::InternalServerError(_error) => {
                write!(f, "There was an error on our side :(")
            }
            AuthError::InvalidToken => {
                write!(f, "Token invalid or expired")
            }
            AuthError::Error(msg) => {
                write!(f, "{msg}")
            }
            AuthError::PasswordConfirmationError => {
                write!(f, "Passwords do not match!")
            }
            AuthError::InvalidPassword => {
                write!(f, "Password does not meet minimum requirements!")
            }
            AuthError::TOTPError => {
                write!(f, "Error validating one time password!")
            }
            AuthError::AccountLocked => {
                write!(f, "Your account has been locked due to invalid attempts. Please try again later or reset your password")
            }
        }
    }
}

// Implement std::fmt::Debug for AppError
impl fmt::Debug for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => {
                write!(f, "Invalid login attempt")
            }
            AuthError::InternalServerError(error) => {
                write!(f, "Internal error: {}", error)
            }
            AuthError::InvalidToken => {
                write!(f, "Invalid token attempt")
            }
            AuthError::Error(msg) => {
                write!(f, "{msg}")
            }
            AuthError::PasswordConfirmationError => {
                write!(f, "Passwords do not match!")
            }
            AuthError::InvalidPassword => {
                write!(f, "Password does not meet minimum requirements!")
            }
            AuthError::TOTPError => {
                write!(f, "Invalid TOTP attempt")
            }
            AuthError::AccountLocked => {
                write!(f, "Account locked")
            }
        }
    }
}
#[cfg(feature = "ssr")]
#[derive(Error, Debug)]
pub enum DBError {
    #[error("User not found: {0}")]
    NotFound(String),
    #[error("Internal server error: {0}")]
    InternalServerError(#[from] diesel::result::Error),
    #[error("Error: {0}")]
    Error(String),
    #[error("Database connection error: {0}")]
    ConnectionError(#[from] diesel::ConnectionError),
}

#[cfg(feature = "ssr")]
impl DBError {
    fn print_to_user(&self) -> &str {
        match self {
            DBError::NotFound(_) => "User not found!",
            DBError::InternalServerError(_) => "There was an error on our side!",
            DBError::Error(msg) => msg,
            DBError::ConnectionError(_) => "There was a connecting error, please try again!",
        }
    }
}

#[cfg(feature = "ssr")]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub pass_hash: String,
}
