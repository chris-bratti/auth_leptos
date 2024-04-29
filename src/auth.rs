use std::env;

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

cfg_if! {
    if #[cfg(feature = "ssr")] {

    use regex::Regex;

/// Hash password with Argon2
fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}

/// Verifies password against hash
fn verify_password(
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

fn generate_password_reset_link() -> Result<String, ServerFnError> {
    use rand::{thread_rng, Rng};
    use rand::distributions::{Alphanumeric};

    let mut rng = thread_rng();

    let generated_link_path: String = (&mut rng).sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    Ok(generated_link_path)
}

fn verify_reset_link(username: &String, reset_link: &String) -> Result<bool, ServerFnError> {
    let link_hash = crate::db::db_helper::get_reset_hash(username).map_err(|_| ServerFnError::new("Unable to get user link"))?;

    match link_hash {
        Some(hash) => {
            verify_password(reset_link, &hash).map_err(|_| ServerFnError::new("Error validation hash"))
        },
        None => Err(ServerFnError::new("User hash not found or has expired"))
    }
}

fn send_reset_email(username: &String, reset_token: &String) -> Result<(), ServerFnError> {

    // TODO: Two DB calls for one transaction is a little gross - will want to slim this down to one call

    let encrypted_email = crate::db::db_helper::get_user_email(&username).map_err(|_| ServerFnError::new("Error fetching user"))?;

    let user = crate::db::db_helper::find_user_by_username(&username).map_err(|_| ServerFnError::new("Error fetching user"))?;

    let name = user.expect("No user present!").first_name;

    let user_email = decrypt_email(encrypted_email).map_err(|_| ServerFnError::new("Error decrypting email"))?;

    smtp::send_email(&user_email, "Reset Password".to_string(), generate_reset_email_body(reset_token, &name), &name);

    Ok(())
}

fn encrypt_email(email: &String) -> Result<String, aes_gcm::Error> {

    let encryption_key = get_env_variable("ENCRYPTION_KEY").expect("ENCRYPTION_KEY is unset!");

    let key = Key::<Aes256Gcm>::from_slice(&encryption_key.as_bytes());

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, email.as_bytes())?;

    //let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    let mut encrypted_data: Vec<u8> = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);


    let output = hex::encode(encrypted_data);
    println!("{}", output);
    Ok(output)
}

fn decrypt_email(encrypted_email: String) -> Result<String, aes_gcm::Error> {

    let encryption_key = get_env_variable("ENCRYPTION_KEY").expect("ENCRYPTION_KEY is unset!");

    let encrypted_data = hex::decode(encrypted_email)
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
async fn login(username: String, password: String) -> Result<(), ServerFnError> {
    // Case insensitive usernames
    let username: String = username.trim().to_lowercase();
    println!("Attempting to log in user {username}");
    // Retrieve pass hash from DB
    let pass_result = crate::db::db_helper::get_pass_hash_for_username(&username)
        .map_err(|_err| ServerFnError::new("Error getting user"));

    // Verify password hash with Argon2
    let verified_result = verify_password(&password, &pass_result?);

    if verified_result.is_err() || !verified_result.unwrap() {
        return Err(ServerFnError::new("Username or password incorrect"));
    }

    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::new("No httpRequest stuff"));
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
) -> Result<(), ServerFnError> {
    // This should have been done on the form submit, but just in case something snuck through
    if confirm_password != password {
        return Err(ServerFnError::new("Username and password do not match"));
    }

    // Do server side password strength validation
    if !check_valid_password(&password) {
        return Err(ServerFnError::new("Password does not meet requirements"));
    }

    // Usernames should case insensitive
    let username: String = username.trim().to_lowercase();

    // Checks db to ensure unique usernames
    match does_user_exist(&username) {
        Ok(username_exists) => {
            if username_exists {
                return Err(ServerFnError::new("That username is already taken"));
            }
        }
        Err(_err) => return Err(ServerFnError::new("Internal server error")),
    }

    // Hash password
    let pass_hash = hash_password(password).expect("Error hashing password");

    let encrypted_email = encrypt_email(&email).expect("Error encrypting email");

    // Create user info to interact with DB
    let user_info = UserInfo {
        username: username.clone(),
        first_name: first_name.clone(),
        last_name,
        pass_hash,
        email: encrypted_email,
    };

    // Creates DB user
    let user =
        create_user(user_info).map_err(|_err| ServerFnError::new("Unable to create user"))?;

    smtp::send_email(
        &email,
        "Welcome!".to_string(),
        generate_welcome_email_body(&first_name),
        &first_name,
    );

    // Saving user to current session to stay logged in
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::new("No httpRequest stuff"));
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
) -> Result<(), ServerFnError> {
    // Retrieve and check if supplied current password matches against store password hash
    let pass_result = crate::db::db_helper::get_pass_hash_for_username(&username)
        .map_err(|_err| ServerFnError::new("Error getting user"));

    let verified_result = verify_password(&current_password, &pass_result?);

    // Check supplied current password is valid
    if verified_result.is_err() || !verified_result.unwrap() {
        return Err(ServerFnError::new("Incorrect password"));
    }

    // Server side password confirmation
    if new_password != confirm_new_password {
        return Err(ServerFnError::new("Passwords do not match"));
    }

    // Do server side password strength validation
    if !check_valid_password(&new_password) {
        return Err(ServerFnError::new("Password does not meet requirements"));
    }

    // Hash new password
    let pass_hash = hash_password(new_password).expect("Error hashing password");

    // Store new password in database
    crate::db::db_helper::update_user_password(&username, &pass_hash)
        .map_err(|_err| ServerFnError::new("Error updating user password"))?;

    // Redirect
    leptos_actix::redirect("/login");

    Ok(())
}

#[server(PasswordReset, "/api")]
pub async fn reset_password(
    username: String,
    password_link: String,
    new_password: String,
    confirm_password: String,
) -> Result<(), ServerFnError> {
    println!("Requesting to reset password");
    // Verify reset link
    let link_verification = verify_reset_link(&username, &password_link)?;

    // If link does not match or is no longer valid, return
    if !link_verification {
        return Err(ServerFnError::new(
            "Error validation link. Link may be expired. Please try again",
        ));
    }

    // Server side password confirmation
    if new_password != confirm_password {
        return Err(ServerFnError::new("Passwords do not match"));
    }

    // Do server side password strength validation
    if !check_valid_password(&new_password) {
        return Err(ServerFnError::new("Password does not meet requirements"));
    }

    // Hash new password
    let pass_hash = hash_password(new_password).expect("Error hashing password");

    // Store new password in database
    crate::db::db_helper::update_user_password(&username, &pass_hash)
        .map_err(|_err| ServerFnError::new("Error updating user password"))?;

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

    // Generate random 32 bit reset link path
    let generated_link = generate_password_reset_link()?;

    // Hash link
    let reset_token = hash_password(generated_link.clone())
        .map_err(|_| ServerFnError::new("Internal server error"))?;

    // Save link hash to DB
    crate::db::db_helper::save_reset(&username, &reset_token)
        .map_err(|_| ServerFnError::new("Internal server error"))?;

    // SMTP send email
    send_reset_email(&username, &generated_link).expect("Error sending email");

    Ok(())
}

#[cfg(test)]
mod test_auth {

    use crate::auth::{check_valid_password, decrypt_email, verify_password};

    use super::{encrypt_email, hash_password};

    #[test]
    fn test_password_hashing() {
        let password = "whatALovelyL!ttleP@s$w0rd".to_string();

        let hashed_password = hash_password(password.clone());

        assert!(hashed_password.is_ok());

        let hashed_password = hashed_password.unwrap();

        assert_ne!(password, hashed_password);

        let pass_match = verify_password(&password, &hashed_password);

        assert!(pass_match.is_ok());

        assert_eq!(pass_match.unwrap(), true);
    }

    #[test]
    fn test_email_encryption() {
        let email = String::from("test@test.com");
        let encrypted_email = encrypt_email(&email).expect("There was an error encrypting");

        assert_ne!(encrypted_email, email);

        let decrypted_email =
            decrypt_email(encrypted_email).expect("There was an error decrypting");

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
