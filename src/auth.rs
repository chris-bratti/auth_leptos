use std::{env, fmt, str::FromStr};

#[cfg(feature = "ssr")]
use actix_identity::Identity;
#[cfg(feature = "ssr")]
use actix_web::HttpMessage;
#[cfg(feature = "ssr")]
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};
#[cfg(feature = "ssr")]
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use cfg_if::cfg_if;
use leptos::*;

#[cfg(feature = "ssr")]
use crate::db::db_helper::create_user;
#[cfg(feature = "ssr")]
use crate::db::db_helper::does_user_exist;
#[cfg(feature = "ssr")]
use crate::db::db_helper::find_user_by_username;
#[cfg(feature = "ssr")]
use crate::db::db_helper::{
    get_verification_hash, is_user_verified, remove_reset_token, remove_verification_token,
    set_user_as_verified,
};
#[cfg(feature = "ssr")]
use crate::server::helpers::get_env_variable;
#[cfg(feature = "ssr")]
use crate::smtp::{self, generate_reset_email_body, generate_welcome_email_body};
#[cfg(feature = "ssr")]
use actix_session::Session;
#[cfg(feature = "ssr")]
use leptos_actix::extract;
#[cfg(feature = "ssr")]
use serde::Deserialize;
#[cfg(feature = "ssr")]
use serde::Serialize;

#[derive(Clone)]
pub enum AuthError {
    InvalidCredentials,
    InternalServerError(String),
    InvalidToken,
    PasswordConfirmationError,
    InvalidPassword,
    Error(String),
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
        }
    }
}

impl FromStr for AuthError {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AuthError::Error(s.to_string()))
    }
}

cfg_if! {
    if #[cfg(feature = "ssr")] {

    use regex::Regex;

/// Hash password with Argon2
fn hash_string(password: String) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}

/// Verifies password against hash
fn verify_hash(
    password: &String,
    password_hash: &String,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(&password_hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Server side password strength validation
fn check_valid_password(password: &String) -> bool{
    // Rust's Regex crate does not support Lookahead matching, so have to break criteria into multiple patterns
    let contains_digit = Regex::new("\\d+").expect("Error parsing regex");
    let contains_capital = Regex::new("[A-Z]+").expect("Error parsing regex");
    let contains_special = Regex::new("[!:@#$^;%&?]+").expect("Error parsing regex");

    let valid = contains_digit.is_match(password) && contains_capital.is_match(password) && contains_special.is_match(password);

    valid && password.len() >= 8 && password.len() <= 16
}

fn generate_token() -> String {
    use rand::{thread_rng, Rng};
    use rand::distributions::{Alphanumeric};

    let mut rng = thread_rng();

    let generated_token: String = (&mut rng).sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    generated_token
}

fn verify_reset_token(username: &String, reset_token: &String) -> Result<bool, ServerFnError<AuthError>> {
    let token_hash = crate::db::db_helper::get_reset_hash(username).map_err(|_| ServerFnError::WrappedServerError(AuthError::InvalidToken))?;

    verify_hash(reset_token, &token_hash).map_err(|_| ServerFnError::WrappedServerError(AuthError::InvalidToken))
}

fn verify_confirmation_token(username: &String, confirmation_token: &String) -> Result<bool, ServerFnError<AuthError>> {
    let verification_hash = get_verification_hash(username).map_err(|_| ServerFnError::WrappedServerError(AuthError::InvalidToken))?;

    verify_hash(confirmation_token, &verification_hash).map_err(|_| ServerFnError::WrappedServerError(AuthError::InvalidToken))
}

fn send_reset_email(username: &String, reset_token: &String) -> Result<(), ServerFnError> {

    // TODO: Two DB calls for one transaction is a little gross - will want to slim this down to one call

    let encrypted_email = crate::db::db_helper::get_user_email(&username).map_err(|_| ServerFnError::new("Error fetching user"))?;

    let user = crate::db::db_helper::find_user_by_username(&username).map_err(|_| ServerFnError::new("Error fetching user"))?;

    let name = user.expect("No user present!").first_name;

    let user_email = decrypt_string(encrypted_email).map_err(|_| ServerFnError::new("Error decrypting email"))?;

    smtp::send_email(&user_email, "Reset Password".to_string(), generate_reset_email_body(reset_token, &name), &name);

    Ok(())
}

fn encrypt_string(data: &String) -> Result<String, aes_gcm::Error> {

    let encryption_key = get_env_variable("ENCRYPTION_KEY").expect("ENCRYPTION_KEY is unset!");

    let key = Key::<Aes256Gcm>::from_slice(&encryption_key.as_bytes());

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, data.as_bytes())?;

    //let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    let mut encrypted_data: Vec<u8> = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);


    let output = hex::encode(encrypted_data);
    Ok(output)
}

fn decrypt_string(encrypted: String) -> Result<String, aes_gcm::Error> {

    let encryption_key = get_env_variable("ENCRYPTION_KEY").expect("ENCRYPTION_KEY is unset!");

    let encrypted_data = hex::decode(encrypted)
        .expect("failed to decode hex string into vec");

    let key = Key::<Aes256Gcm>::from_slice(encryption_key.as_bytes());

    // 12 digit nonce is prepended to encrypted data. Split nonce from encrypted email
    let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_arr);

    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher.decrypt(nonce, ciphered_data)
        .expect("failed to decrypt data");

    Ok(String::from_utf8(plaintext)
        .expect("failed to convert vector of bytes to string"))
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

#[server]
pub async fn get_session() -> Result<String, ServerFnError> {
    let session: Session = extract().await?;

    if let Some(count) = session.get::<i32>("counter")? {
        // modify the session state
        session.insert("counter", count + 1)?;
        println!("SESSION value: {}", count + 1);
    } else {
        println!("Starting session with count 1");
        session.insert("counter", 1)?;
    }

    Ok(String::from("Goat"))
}

/// Server function to log in user
#[server(Login, "/api")]
async fn login(username: String, password: String) -> Result<(), ServerFnError<AuthError>> {
    // Case insensitive usernames
    let username: String = username.trim().to_lowercase();
    // Retrieve pass hash from DB
    let pass_result = crate::db::db_helper::get_pass_hash_for_username(&username)
        .map_err(|_err| ServerFnError::WrappedServerError(AuthError::InvalidCredentials));

    // Verify password hash with Argon2
    let verified_result = verify_hash(&password, &pass_result?);

    if verified_result.is_err() || !verified_result.unwrap() {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InvalidCredentials,
        ));
    }

    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    // Attach user to current session
    Identity::login(&req.extensions(), username.into()).unwrap();

    // Redirect
    leptos_actix::redirect("/user");

    Ok(())
}

/// Retrieves the User information based on username in current session
#[server]
pub async fn get_user_from_session() -> Result<crate::User, ServerFnError> {
    // Extract Actix Identity
    let user: Option<Identity> = extract().await?;

    let session: Session = extract().await?;

    match session.get::<String>("actix_identity.user_id").unwrap() {
        Some(user) => println!("Found user in session: {user}"),
        None => println!("No user in session"),
    }

    // If user exists in session, gets User entry from DB
    if let Some(user) = user {
        match find_user_by_username(&user.id().unwrap()) {
            Ok(some_user) => match some_user {
                Some(user) => Ok(user),
                None => Err(ServerFnError::new("No user found")),
            },
            Err(_err) => Err(ServerFnError::new("Internal server error")),
        }
    } else {
        println!("No user found");
        Err(ServerFnError::new("No user found"))
    }
}

/// Server function to create a new user
#[server(SignUp, "/api")]
pub async fn signup(
    first_name: String,
    last_name: String,
    username: String,
    password: String,
    email: String,
    confirm_password: String,
) -> Result<(), ServerFnError<AuthError>> {
    // This should have been done on the form submit, but just in case something snuck through
    if confirm_password != password {
        return Err(ServerFnError::WrappedServerError(
            AuthError::PasswordConfirmationError,
        ));
    }

    // Do server side password strength validation
    if !check_valid_password(&password) {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InvalidPassword,
        ));
    }

    // Usernames should case insensitive
    let username: String = username.trim().to_lowercase();

    // Checks db to ensure unique usernames
    match does_user_exist(&username) {
        Ok(username_exists) => {
            if username_exists {
                return Err(ServerFnError::WrappedServerError(AuthError::Error(
                    "Invalid username!".to_string(),
                )));
            }
        }
        Err(err) => {
            return Err(ServerFnError::WrappedServerError(
                AuthError::InternalServerError(err.to_string()),
            ))
        }
    }

    // TODO: Check to ensure unique emails - Maybe I'll end up eliminating usernames all together

    // Hash password
    let pass_hash = hash_string(password).expect("Error hashing password");

    let encrypted_email = encrypt_string(&email).expect("Error encrypting email");

    // Create user info to interact with DB
    let user_info = UserInfo {
        username: username.clone(),
        first_name: first_name.clone(),
        last_name,
        pass_hash,
        email: encrypted_email,
    };

    // Creates DB user
    let user = create_user(user_info).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    // Generate random 32 bit reset token path
    let generated_token = generate_token();

    // Hash token
    let verification_token = hash_string(generated_token.clone()).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    // Save token hash to DB
    crate::db::db_helper::save_verification(&username, &verification_token).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    // Send welcome email
    smtp::send_email(
        &email,
        "Welcome!".to_string(),
        generate_welcome_email_body(&first_name, &generated_token),
        &first_name,
    );

    // Saving user to current session to stay logged in
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("Unable to find HttpRequest in context".to_string()),
        ));
    };
    println!("Saving user to session: {}", user.username);
    Identity::login(&req.extensions(), user.username.into()).unwrap();

    leptos_actix::redirect("/user");

    Ok(())
}

/// Server function to update user password
#[server(UpdatePassword, "/api")]
pub async fn change_password(
    username: String,
    current_password: String,
    new_password: String,
    confirm_new_password: String,
) -> Result<(), ServerFnError<AuthError>> {
    // Retrieve and check if supplied current password matches against store password hash
    let pass_result = crate::db::db_helper::get_pass_hash_for_username(&username).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    });

    let verified_result = verify_hash(&current_password, &pass_result?);

    // Check supplied current password is valid
    if verified_result.is_err() || !verified_result.unwrap() {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InvalidCredentials,
        ));
    }

    // Server side password confirmation
    if new_password != confirm_new_password {
        return Err(ServerFnError::WrappedServerError(
            AuthError::PasswordConfirmationError,
        ));
    }

    // Do server side password strength validation
    if !check_valid_password(&new_password) {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InvalidPassword,
        ));
    }

    // Hash new password
    let pass_hash = hash_string(new_password).expect("Error hashing password");

    // Store new password in database
    crate::db::db_helper::update_user_password(&username, &pass_hash).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    // Redirect
    leptos_actix::redirect("/login");

    Ok(())
}

#[server(PasswordReset, "/api")]
pub async fn reset_password(
    username: String,
    reset_token: String,
    new_password: String,
    confirm_password: String,
) -> Result<(), ServerFnError<AuthError>> {
    println!("Requesting to reset password");
    // Verify reset token
    let token_verification = verify_reset_token(&username, &reset_token)?;

    // If token does not match or is no longer valid, return
    if !token_verification {
        return Err(ServerFnError::WrappedServerError(AuthError::InvalidToken));
    }

    // Server side password confirmation
    if new_password != confirm_password {
        return Err(ServerFnError::WrappedServerError(
            AuthError::PasswordConfirmationError,
        ));
    }

    // Do server side password strength validation
    if !check_valid_password(&new_password) {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InvalidPassword,
        ));
    }

    // Hash new password
    let pass_hash = hash_string(new_password).expect("Error hashing password");

    // Store new password in database
    crate::db::db_helper::update_user_password(&username, &pass_hash).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    remove_reset_token(&username).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;
    // Redirect
    leptos_actix::redirect("/login");

    Ok(())
}

#[server(RequestPasswordReset, "/api")]
pub async fn request_password_reset(username: String) -> Result<(), ServerFnError> {
    // Checks if user exists. If it doesn't, stops process but produces no error
    // This is to maintain username security
    match does_user_exist(&username) {
        Ok(username_exists) => {
            if !username_exists {
                return Ok(());
            }
        }
        Err(_err) => return Err(ServerFnError::new("Internal server error")),
    }
    // Redirects user home
    leptos_actix::redirect("/");

    // Generate random 32 bit reset token path
    let generated_token = generate_token();

    // Hash token
    let reset_token = hash_string(generated_token.clone())
        .map_err(|_| ServerFnError::new("Internal server error"))?;

    // Save token hash to DB
    crate::db::db_helper::save_reset(&username, &reset_token)
        .map_err(|_| ServerFnError::new("Internal server error"))?;

    // SMTP send email
    send_reset_email(&username, &generated_token).expect("Error sending email");

    Ok(())
}

#[server(VerifyUser, "/api")]
pub async fn verify_user(
    username: String,
    verification_token: String,
) -> Result<(), ServerFnError<AuthError>> {
    println!("Attempting to verify user");
    // Verify reset token
    let token_verification = verify_confirmation_token(&username, &verification_token)?;

    // If token does not match or is no longer valid, return
    if !token_verification {
        return Err(ServerFnError::WrappedServerError(AuthError::InvalidToken));
    }

    set_user_as_verified(&username)
        .map_err(|_| ServerFnError::new("Error verifying user. Please contact us"))
        .expect("Error setting user as verified");

    remove_verification_token(&username).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    leptos_actix::redirect("/login");

    Ok(())
}

#[server(IsUserVerified, "/api")]
pub async fn check_user_verification(username: String) -> Result<bool, ServerFnError> {
    let verified = is_user_verified(&username)
        .map_err(|err| ServerFnError::new(format!("Error verifying user: {}", err.to_string())))?;

    println!("User verification: {}", verified);
    Ok(verified)
}

#[cfg(test)]
mod test_auth {

    use crate::auth::{check_valid_password, decrypt_string, verify_hash};

    use super::{encrypt_string, hash_string};

    #[test]
    fn test_password_hashing() {
        let password = "whatALovelyL!ttleP@s$w0rd".to_string();

        let hashed_password = hash_string(password.clone());

        assert!(hashed_password.is_ok());

        let hashed_password = hashed_password.unwrap();

        assert_ne!(password, hashed_password);

        let pass_match = verify_hash(&password, &hashed_password);

        assert!(pass_match.is_ok());

        assert_eq!(pass_match.unwrap(), true);
    }

    #[test]
    fn test_email_encryption() {
        let email = String::from("test@test.com");
        let encrypted_email = encrypt_string(&email).expect("There was an error encrypting");

        assert_ne!(encrypted_email, email);

        let decrypted_email =
            decrypt_string(encrypted_email).expect("There was an error decrypting");

        assert_eq!(email, decrypted_email);
    }

    #[test]
    fn test_password_validation() {
        let valid_password = String::from("Password123!");

        assert!(check_valid_password(&valid_password));

        let valid_password = String::from("g00dP@ssw0rd2");

        assert!(check_valid_password(&valid_password));

        let invalid_password = String::from("password2");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("Thispasswordislongerthanwhatisallowed222222!!!!!");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("$H0rt");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("nocapital123!");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("noSpecial1112");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("noNumbers!!");

        assert!(!check_valid_password(&invalid_password));
    }
}
