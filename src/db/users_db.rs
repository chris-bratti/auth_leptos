use crate::db::models::{DBResetToken, DBUser, DBVerificationToken, NewDBResetToken, NewDBUser};
use crate::db::schema::{self, password_reset_tokens};
use diesel::pg::PgConnection;
use diesel::{prelude::*, select};
use dotenvy::dotenv;
use std::env;
use std::time::Duration;

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

pub fn get_reset_token_from_db(
    uname: &String,
) -> Result<Option<DBResetToken>, diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    let db_user = users
        .filter(username.eq(uname))
        .select(DBUser::as_select())
        .get_result(&mut connection)?;

    // get pages for a book
    let pass_reset_token = DBResetToken::belonging_to(&db_user)
        .limit(1)
        .select(DBResetToken::as_select())
        .first(&mut connection)
        .optional()?;

    Ok(pass_reset_token)
}

pub fn save_reset_token_to_db(
    uname: &String,
    rtoken: &String,
) -> Result<(), diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut connection)?;

    // Gets 20 minutes from current time
    let token_expiry = now
        .checked_add(Duration::new(1200, 0))
        .expect("Error parsing time");

    let db_user: Option<DBUser> = users
        .filter(username.eq(uname))
        .limit(1)
        .select(DBUser::as_select())
        .first(&mut connection)
        .optional()?;

    match db_user {
        Some(user) => {
            let db_reset_token = NewDBResetToken {
                reset_token: rtoken,
                reset_token_expiry: &token_expiry,
                user_id: &user.id,
            };
            diesel::insert_into(password_reset_tokens::table)
                .values(&db_reset_token)
                .returning(DBResetToken::as_returning())
                .get_result(&mut connection)?;
            Ok(())
        }
        None => Err(diesel::result::Error::NotFound),
    }
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

    use crate::{
        auth::UserInfo,
        db::users_db::{
            delete_db_user, get_user_from_username, update_db_password, update_db_username,
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
}
