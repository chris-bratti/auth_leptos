use std::{env, str::FromStr};

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
use crate::db::db_helper::*;
#[cfg(feature = "ssr")]
use crate::server::helpers::get_env_variable;
#[cfg(feature = "ssr")]
use crate::smtp::{self, generate_reset_email_body, generate_welcome_email_body};
use crate::AuthError;
#[cfg(feature = "ssr")]
use crate::UserInfo;
#[cfg(feature = "ssr")]
use leptos_actix::extract;

#[cfg(feature = "ssr")]
use log::{error, info, warn};

impl FromStr for AuthError {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AuthError::Error(s.to_string()))
    }
}

cfg_if! {
    if #[cfg(feature = "ssr")] {

    use totp_rs::{Algorithm, TOTP, Secret};


    use regex::Regex;

    enum EncryptionKey {
        SmtpKey,
        TwoFactorKey,
        LoggerKey,
    }

    impl EncryptionKey {
        pub fn get(&self) -> String {
            let key = match self {
                EncryptionKey::SmtpKey => "SMTP_ENCRYPTION_KEY",
                EncryptionKey::TwoFactorKey => "TWO_FACTOR_KEY",
                EncryptionKey::LoggerKey => "LOG_KEY"
            };

            get_env_variable(key).expect("Encryption key is unset!")
        }
    }

fn get_totp_config(username: &String, token: &String) -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(token.as_bytes().to_vec()).to_bytes().unwrap(),
        Some("Auth Leptos".to_string()),
        username.to_string(),
    ).unwrap()
}

async fn create_2fa_for_user(username: String) -> Result<(String, String), AuthError>{
    let token = generate_token().await;
    let totp = get_totp_config(&username, &token);
    let qr_code = totp.get_qr_base64().expect("Error generating QR code");
    Ok((qr_code, token))
}

async fn get_totp(username: &String) -> Result<String, AuthError> {
    let token = get_user_2fa_token(&username).map_err(|err| AuthError::InternalServerError(err.to_string()))?;
    match token{
        Some(token) =>{
            let decrypted_token = decrypt_string(token, EncryptionKey::TwoFactorKey).await.expect("Error decrypting string!");
            get_totp_config(&username, &decrypted_token).generate_current().map_err(|err| AuthError::InternalServerError(err.to_string()))
        },
        None => Err(AuthError::TOTPError)
    }
}

/// Hash password with Argon2
async fn hash_string(password: String) -> Result<String, argon2::password_hash::Error> {
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

async fn generate_token() -> String {
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

async fn send_reset_email(username: &String, reset_token: &String) -> Result<(), ServerFnError> {

    // TODO: Two DB calls for one transaction is a little gross - will want to slim this down to one call

    let encrypted_email = crate::db::db_helper::get_user_email(&username).map_err(|_| ServerFnError::new("Error fetching user"))?;

    let user = crate::db::db_helper::find_user_by_username(&username).map_err(|_| ServerFnError::new("Error fetching user"))?;

    let name = user.expect("No user present!").first_name;

    let user_email = decrypt_string(encrypted_email, EncryptionKey::SmtpKey).await.map_err(|_| ServerFnError::new("Error decrypting email"))?;

    smtp::send_email(&user_email, "Reset Password".to_string(), generate_reset_email_body(reset_token, &name), &name).await;

    Ok(())
}

async fn encrypt_string(data: &String, encryption_key: EncryptionKey) -> Result<String, aes_gcm::Error> {

    let encryption_key = encryption_key.get();

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

async fn decrypt_string(encrypted: String, encryption_key: EncryptionKey) -> Result<String, aes_gcm::Error> {

    let encryption_key = encryption_key.get();

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

/// Server function to log in user
#[server(Login, "/api")]
async fn login(
    username: String,
    password: String,
) -> Result<Option<(bool, String)>, ServerFnError<AuthError>> {
    let encrypted_username: String = encrypt_string(&username, EncryptionKey::LoggerKey)
        .await
        .expect("Error encrypting username");

    info!("Logging in user: {}", encrypted_username);

    // Case insensitive usernames
    let username: String = username.trim().to_lowercase();

    if is_user_locked(&username)
        .map_err(|_| ServerFnError::WrappedServerError(AuthError::InvalidCredentials))?
    {
        warn!("Locked user attempt: {}", &encrypted_username);
        return Err(ServerFnError::WrappedServerError(AuthError::AccountLocked));
    }

    // Retrieve pass hash from DB
    let pass_result = crate::db::db_helper::get_pass_hash_for_username(&username)
        .map_err(|_err| ServerFnError::WrappedServerError(AuthError::InvalidCredentials));

    // Verify password hash with Argon2
    let verified_result = verify_hash(&password, &pass_result?);

    if verified_result.is_err() || !verified_result.unwrap() {
        warn!("Invalid password attempt for user: {}", &encrypted_username);
        let user_not_locked =
            failed_login_attempt(&username).expect("Error marking login attempt as failed");

        if !user_not_locked {
            return Err(ServerFnError::WrappedServerError(AuthError::AccountLocked));
        }
        return Err(ServerFnError::WrappedServerError(
            AuthError::InvalidCredentials,
        ));
    }

    let two_factor = user_has_2fa_enabled(&username).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    info!("User OTP: {}", two_factor);

    if two_factor {
        return Ok(Some((true, username)));
    }

    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    // Attach user to current session
    Identity::login(&req.extensions(), username.clone().into()).unwrap();

    // Redirect
    leptos_actix::redirect("/user");

    Ok(None)
}

/// Retrieves the User information based on username in current session
#[server]
pub async fn get_user_from_session() -> Result<crate::User, ServerFnError> {
    // Extract Actix Identity
    let user: Option<Identity> = extract().await?;

    //let session: Session = extract().await?;

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
        error!("No user found");
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

    let encrypted_username = encrypt_string(&username, EncryptionKey::LoggerKey)
        .await
        .expect("Error encrypting username");

    info!("Signing up user: {}", &encrypted_username);

    // TODO: Check to ensure unique emails - Maybe I'll end up eliminating usernames all together

    // Hash password
    let pass_hash = hash_string(password);

    let encrypted_email = encrypt_string(&email, EncryptionKey::SmtpKey);

    // Create user info to interact with DB
    let user_info = UserInfo {
        username: username.clone(),
        first_name: first_name.clone(),
        last_name,
        pass_hash: pass_hash.await.expect("Error hashing password"),
        email: encrypted_email.await.expect("Error encrypting email"),
    };

    // Creates DB user
    let user = create_user(user_info);
    // Generate random 32 bit verification token path
    let generated_token = generate_token().await;

    // Hash token
    let verification_token = hash_string(generated_token.clone()).await.map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    let user = user.await.map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    // Save token hash to DB
    crate::db::db_helper::save_verification(&username, &verification_token).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    // Send welcome email
    let email_sent = smtp::send_email(
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
    info!("Saving user to session: {}", &encrypted_username);
    Identity::login(&req.extensions(), user.username.into()).unwrap();

    email_sent.await;

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

    info!(
        "Changing password for user: {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );

    // Hash new password
    let pass_hash = hash_string(new_password)
        .await
        .expect("Error hashing password");

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
    info!(
        "Requesting to reset password for user {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );
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
    let pass_hash = hash_string(new_password)
        .await
        .expect("Error hashing password");

    // Store new password in database
    crate::db::db_helper::update_user_password(&username, &pass_hash).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    remove_reset_token(&username).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    unlock_user(&username).map_err(|err| {
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
    let generated_token = generate_token().await;

    // Hash token
    let reset_token = hash_string(generated_token.clone())
        .await
        .map_err(|_| ServerFnError::new("Internal server error"))?;

    // Save token hash to DB
    crate::db::db_helper::save_reset(&username, &reset_token)
        .map_err(|_| ServerFnError::new("Internal server error"))?;

    // SMTP send email
    send_reset_email(&username, &generated_token)
        .await
        .expect("Error sending email");

    Ok(())
}

#[server(VerifyUser, "/api")]
pub async fn verify_user(
    username: String,
    verification_token: String,
) -> Result<(), ServerFnError<AuthError>> {
    info!(
        "Attempting to verify user {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );
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

#[server(Generate2FA, "/api")]
pub async fn generate_2fa(username: String) -> Result<(String, String), ServerFnError<AuthError>> {
    let (qr_code, token) = create_2fa_for_user(username)
        .await
        .map_err(|err| ServerFnError::WrappedServerError(err))?;
    Ok((qr_code, token))
}

#[server(Enable2FA, "/api")]
pub async fn enable_2fa(
    username: String,
    two_factor_token: String,
    otp: String,
) -> Result<bool, ServerFnError<AuthError>> {
    let totp = get_totp_config(&username, &two_factor_token);

    let generated_token = totp.generate_current().expect("Error generating token");

    if generated_token != otp {
        return Err(ServerFnError::WrappedServerError(AuthError::TOTPError));
    }

    let encrypted_token = encrypt_string(&two_factor_token, EncryptionKey::TwoFactorKey)
        .await
        .expect("Error encrypting token");
    enable_2fa_for_user(&username, &encrypted_token).map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;

    Ok(true)
}

#[server(VerifyOTP, "/api")]
pub async fn verify_otp(otp: String, username: String) -> Result<bool, ServerFnError<AuthError>> {
    info!(
        "Verifying OTP for {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );
    let otp = otp.trim().to_string();
    let totp = get_totp(&username)
        .await
        .expect("Error validating token")
        .trim()
        .to_string();

    if !otp.eq(&totp) {
        return Err(ServerFnError::WrappedServerError(AuthError::TOTPError));
    }

    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    // Attach user to current session
    Identity::login(&req.extensions(), username.clone().into()).unwrap();

    // Redirect
    leptos_actix::redirect("/user");

    Ok(true)
}

#[server(Logout, "/api")]
pub async fn logout() -> Result<(), ServerFnError<AuthError>> {
    let identity: Option<Identity> = extract().await.map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;
    info!("Logging out...");
    Identity::logout(identity.expect("No user found in session!"));
    leptos_actix::redirect("/");
    Ok(())
}

#[cfg(test)]
mod test_auth {

    use core::{assert_eq, assert_ne};

    use crate::auth::{check_valid_password, decrypt_string, verify_hash, EncryptionKey};

    use super::{encrypt_string, get_totp_config, hash_string};

    #[tokio::test]
    async fn test_password_hashing() {
        let password = "whatALovelyL!ttleP@s$w0rd".to_string();

        let hashed_password = hash_string(password.clone()).await;

        assert!(hashed_password.is_ok());

        let hashed_password = hashed_password.unwrap();

        assert_ne!(password, hashed_password);

        let pass_match = verify_hash(&password, &hashed_password);

        assert!(pass_match.is_ok());

        assert_eq!(pass_match.unwrap(), true);
    }

    #[tokio::test]
    async fn test_email_encryption() {
        let email = String::from("test@test.com");
        let encrypted_email = encrypt_string(&email, EncryptionKey::SmtpKey)
            .await
            .expect("There was an error encrypting");

        assert_ne!(encrypted_email, email);

        let decrypted_email = decrypt_string(encrypted_email, EncryptionKey::SmtpKey)
            .await
            .expect("There was an error decrypting");

        assert_eq!(email, decrypted_email);
    }

    #[tokio::test]
    async fn test_log_encryption() {
        let username = String::from("testuser123");
        let encrypted_username = encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("There was an error encrypting!");

        assert_ne!(encrypted_username, username);

        let decrypted_username = decrypt_string(encrypted_username, EncryptionKey::LoggerKey)
            .await
            .expect("There was an error decrypting!");

        assert_eq!(username, decrypted_username);
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

    #[test]
    fn test_totp() {
        let token = "TestSecretSuperSecret".to_string();
        let username = "exampleuser".to_string();

        let totp1 = get_totp_config(&username, &token);

        let totp2 = get_totp_config(&username, &token);

        let otp1 = totp1.generate_current().expect("Error generating OTP");

        let otp2 = totp2.generate_current().expect("Error generating OTP");

        assert_eq!(otp1, otp2);
    }
}
