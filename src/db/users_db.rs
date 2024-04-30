use crate::db::models::{DBUser, NewDBUser};
use crate::db::schema::{self};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenvy::dotenv;
use schema::users::dsl::*;
use std::env;

use super::schema::users;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn create_db_user(user_info: crate::auth::UserInfo) -> Result<DBUser, diesel::result::Error> {
    let mut conn = establish_connection();
    let new_user = NewDBUser {
        first_name: &user_info.first_name,
        last_name: &user_info.last_name,
        username: &user_info.username,
        pass_hash: &user_info.pass_hash,
        email: &user_info.email,
        verified: &false,
    };

    println!("{:#?}", new_user);

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(DBUser::as_returning())
        .get_result(&mut conn)
}

pub fn get_user_from_username(uname: &String) -> Result<Option<DBUser>, diesel::result::Error> {
    use schema::users::dsl::*;
    let mut connection = establish_connection();

    users
        .filter(username.eq(uname))
        .limit(1)
        .select(DBUser::as_select())
        .first(&mut connection)
        .optional()
}

pub fn set_db_user_as_verified(uname: &String) -> Result<DBUser, diesel::result::Error> {
    let mut connection = establish_connection();

    diesel::update(users.filter(username.eq(uname)))
        .set(verified.eq(true))
        .returning(DBUser::as_returning())
        .get_result(&mut connection)
}

pub fn update_db_username(
    uname: &String,
    new_uname: &String,
) -> Result<DBUser, diesel::result::Error> {
    use schema::users::dsl::*;
    let mut connection = establish_connection();

    diesel::update(users.filter(username.eq(uname)))
        .set(username.eq(new_uname))
        .returning(DBUser::as_returning())
        .get_result(&mut connection)
}

pub fn update_db_password(
    uname: &String,
    new_pass: &String,
) -> Result<DBUser, diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    diesel::update(users.filter(username.eq(uname)))
        .set(pass_hash.eq(new_pass))
        .returning(DBUser::as_returning())
        .get_result(&mut connection)
}

pub fn delete_db_user(uname: &String) -> Result<usize, diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    diesel::delete(users.filter(username.eq(uname))).execute(&mut connection)
}

#[cfg(test)]
pub mod test_db {

    use chrono::{DateTime, Utc};

    use crate::{
        auth::UserInfo,
        db::{
            reset_token_table::{
                delete_db_reset_token, get_reset_token_from_db, save_reset_token_to_db,
            },
            users_db::{
                delete_db_user, get_user_from_username, update_db_password, update_db_username,
            },
            verification_tokens_table::{
                delete_db_verification_token, get_verification_token_from_db,
                save_verification_token_to_db,
            },
        },
    };

    use super::create_db_user;

    #[test]
    fn test_user_crud() {
        let user_info = UserInfo {
            first_name: String::from("Foo"),
            last_name: String::from("Barley"),
            username: String::from("foobar"),
            pass_hash: String::from("superdupersecrethash"),
            email: String::from("foo@bar.com"),
        };

        // Create
        let db_user = create_db_user(user_info.clone()).expect("Error creating user");

        assert_eq!(db_user.first_name, user_info.first_name);
        assert_eq!(db_user.last_name, user_info.last_name);
        assert_eq!(db_user.username, user_info.username);
        assert_eq!(db_user.pass_hash, user_info.pass_hash);

        // Read
        let read_db_user =
            get_user_from_username(&user_info.username).expect("Error reading user from db");

        assert!(read_db_user.is_some());

        let read_db_user = read_db_user.unwrap();

        assert_eq!(db_user.first_name, read_db_user.first_name);
        assert_eq!(db_user.last_name, read_db_user.last_name);
        assert_eq!(db_user.username, read_db_user.username);
        assert_eq!(db_user.pass_hash, read_db_user.pass_hash);

        // Update - username
        let new_username = String::from("barfoo");
        let updated_db_user = update_db_username(&user_info.username, &new_username);

        assert!(updated_db_user.is_ok());

        let updated_db_user = updated_db_user.unwrap();

        assert_eq!(db_user.first_name, updated_db_user.first_name);
        assert_eq!(db_user.last_name, updated_db_user.last_name);
        assert_ne!(db_user.username, updated_db_user.username);
        assert_eq!(db_user.pass_hash, updated_db_user.pass_hash);

        assert_eq!(updated_db_user.username, new_username);

        // Update - password
        let new_password = String::from("newsecretpassword");
        let updated_db_user = update_db_password(&String::from("barfoo"), &new_password);
        assert!(updated_db_user.is_ok());

        let updated_db_user = updated_db_user.unwrap();

        assert_eq!(db_user.first_name, updated_db_user.first_name);
        assert_eq!(db_user.last_name, updated_db_user.last_name);
        assert_ne!(db_user.pass_hash, updated_db_user.pass_hash);

        assert_eq!(updated_db_user.username, new_username);
        assert_eq!(updated_db_user.pass_hash, new_password);

        // Delete

        let count = delete_db_user(&new_username);

        assert!(count.is_ok());

        let count = count.unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_reset_tokens() {
        let user_info = UserInfo {
            first_name: String::from("Foo"),
            last_name: String::from("Barley"),
            username: String::from("veryunique"),
            pass_hash: String::from("superdupersecrethash"),
            email: String::from("foo@bar.com"),
        };

        // Create a new user
        let _db_user = create_db_user(user_info.clone()).expect("Error creating user");

        let reset_token = String::from("superSecrettokenHash");

        // Create reset token for user
        save_reset_token_to_db(&user_info.username, &reset_token).expect("Error saving to DB");

        // Read reset token
        let retrieved_token =
            get_reset_token_from_db(&user_info.username).expect("Error reading from DB");

        assert!(retrieved_token.is_some());

        let retrieved_token = retrieved_token.unwrap();

        // Make sure reset token is the same
        assert_eq!(reset_token, retrieved_token.reset_token);

        // Make sure the expiration timestamp was create correctly
        let expiry = retrieved_token.reset_token_expiry;
        let timestamp: DateTime<Utc> = DateTime::from(expiry);

        // Get the current time
        let current_time = Utc::now();

        // Calculate the difference in minutes
        let time_until_expiry = current_time.signed_duration_since(timestamp).num_minutes();

        assert!(time_until_expiry >= -20);

        let count =
            delete_db_reset_token(&user_info.username).expect("Error deleting reset token!");

        assert_eq!(count, 1);

        let count = delete_db_user(&user_info.username).expect("Error deleting user!");

        assert_eq!(count, 1);
    }

    #[test]
    fn test_verification_tokens() {
        let user_info = UserInfo {
            first_name: String::from("Foo"),
            last_name: String::from("Barley"),
            username: String::from("evenmoreunique"),
            pass_hash: String::from("superdupersecrethash"),
            email: String::from("foo@bar.com"),
        };

        // Create a new user
        let _db_user = create_db_user(user_info.clone()).expect("Error creating user");

        let verification_token = String::from("superSecrettokenHash");

        // Create reset token for user
        save_verification_token_to_db(&user_info.username, &verification_token)
            .expect("Error saving to DB");

        // Read reset token
        let retrieved_token =
            get_verification_token_from_db(&user_info.username).expect("Error reading from DB");

        assert!(retrieved_token.is_some());

        let retrieved_token = retrieved_token.unwrap();

        // Make sure reset token is the same
        assert_eq!(verification_token, retrieved_token.confirm_token);

        // Make sure the expiration timestamp was create correctly
        let expiry = retrieved_token.confirm_token_expiry;
        let timestamp: DateTime<Utc> = DateTime::from(expiry);

        // Get the current time
        let current_time = Utc::now();

        // Calculate the difference in minutes
        let time_until_expiry = current_time.signed_duration_since(timestamp).num_minutes();

        assert!(time_until_expiry >= -20);

        let count =
            delete_db_verification_token(&user_info.username).expect("Error deleting reset token!");

        assert_eq!(count, 1);

        let count = delete_db_user(&user_info.username).expect("Error deleting user!");

        assert_eq!(count, 1);
    }
}
