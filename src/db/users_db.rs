use crate::db::models::{DBUser, NewDBUser};
use crate::db::schema;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;

use super::schema::users;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn create_user(user_info: crate::auth::UserInfo) -> DBUser {
    let mut conn = establish_connection();
    let new_user = NewDBUser {
        first_name: &user_info.first_name,
        last_name: &user_info.last_name,
        username: &user_info.username,
        pass_hash: &user_info.pass_hash,
    };

    println!("{:#?}", new_user);

    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(DBUser::as_returning())
        .get_result(&mut conn)
        .expect("ERROR saving new user")
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

pub fn show_users(connection: &mut PgConnection) {
    use schema::users::dsl::*;
    let results = users
        //.filter(published.eq(true))
        .limit(5)
        .select(DBUser::as_select())
        .load(connection)
        .expect("Error loading users");

    println!("Displaying {} users", results.len());
    for user in results {
        println!("{}", user.username);
        println!("{}", user.first_name);
        println!("{}", user.last_name);
    }
}
