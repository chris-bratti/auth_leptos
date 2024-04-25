use crate::db::schema::*;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::db::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DBUser {
    pub id: i32,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub pass_hash: String,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewDBUser<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub username: &'a str,
    pub pass_hash: &'a str,
}
