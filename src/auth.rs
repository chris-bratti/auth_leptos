#[cfg(feature = "ssr")]
use actix_identity::Identity;
#[cfg(feature = "ssr")]
use actix_web::HttpMessage;
#[cfg(feature = "ssr")]
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use cfg_if::cfg_if;
use leptos::*;

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
fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}

fn verify_password(
    password: &String,
    password_hash: &String,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(&password_hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
    }
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

#[server(Login, "/api")]
async fn login(username: String, password: String) -> Result<(), ServerFnError> {
    println!("Attempting to log in user {username}");
    let pass_result = crate::db::db::get_pass_hash_for_username(username.clone());

    let verified_result = verify_password(&password, &pass_result?);

    if verified_result.is_err() || !verified_result.unwrap() {
        return Err(ServerFnError::new("Username or password incorrect"));
    }

    // attach a verified user identity to the active session
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::new("No httpRequest stuff"));
    };

    Identity::login(&req.extensions(), username.into()).unwrap();

    leptos_actix::redirect("/user");

    Ok(())
}

#[server]
pub async fn get_user() -> Result<String, ServerFnError> {
    let user: Option<Identity> = extract().await?;

    let session: Session = extract().await?;

    match session.get::<String>("actix_identity.user_id").unwrap() {
        Some(user) => println!("Found user in session: {user}"),
        None => println!("No user in session"),
    }

    if let Some(user) = user {
        println!("User found");
        Ok(user.id().unwrap())
    } else {
        println!("No user found");
        Err(ServerFnError::new("No user found"))
    }
}

pub async fn validate_credentials() {}

#[server(SignUp, "/api")]
pub async fn signup(
    first_name: String,
    last_name: String,
    username: String,
    password: String,
    confirm_password: String,
) -> Result<(), ServerFnError> {
    use crate::db::db::*;

    let mut conn = establish_connection();

    // TODO: Verify Username

    let pass_hash = hash_password(password).expect("Error hashing password");

    let user_info = UserInfo {
        username: username.clone(),
        first_name,
        last_name,
        pass_hash,
    };

    create_user(&mut conn, user_info);

    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::new("No httpRequest stuff"));
    };
    println!("Saving user to session: {username}");
    Identity::login(&req.extensions(), username.into()).unwrap();

    leptos_actix::redirect("/user");

    Ok(())
}

#[cfg(feature = "ssr")]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub pass_hash: String,
}

#[cfg(test)]
mod test_auth {
    use crate::auth::verify_password;

    use super::hash_password;

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
}
