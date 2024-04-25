use std::fmt;

use crate::{auth::UserInfo, User};

use super::users_db::{
    create_db_user, delete_db_user, get_user_from_username, update_db_password, update_db_username,
};

pub fn does_user_exist(username: &String) -> Result<bool, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    Ok(db_user.is_some())
}

pub fn get_pass_hash_for_username(username: &String) -> Result<String, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    match db_user {
        Some(user) => Ok(user.pass_hash),
        None => Err(DBError::NotFound(username.clone())),
    }
}

pub fn update_user_password(
    username: &String,
    old_pass_hash: &String,
    new_pass_hash: &String,
) -> Result<(), DBError> {
    update_db_password(username, old_pass_hash, new_pass_hash)
        .map_err(|err| DBError::InternalServerError(err))?;

    Ok(())
}

pub fn create_user(user_info: UserInfo) -> Result<User, DBError> {
    let db_user = create_db_user(user_info).map_err(|err| DBError::InternalServerError(err))?;

    let user = User {
        first_name: db_user.first_name,
        last_name: db_user.last_name,
        username: db_user.username,
    };

    Ok(user)
}

pub fn find_user_by_username(username: &String) -> Result<Option<User>, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    match db_user {
        Some(db_user) => {
            let user = User {
                first_name: db_user.first_name,
                last_name: db_user.last_name,
                username: db_user.username,
            };
            Ok(Some(user))
        }
        None => Ok(None),
    }
}

pub fn update_username(username: &String, new_username: &String) -> Result<(), DBError> {
    let db_user = update_db_username(username, new_username);

    match db_user {
        Ok(_) => Ok(()),
        Err(err) => match err {
            diesel::result::Error::NotFound => Err(DBError::NotFound(username.clone())),
            _ => Err(DBError::InternalServerError(err)),
        },
    }
}

pub fn delete_user(username: &String) -> Result<(), DBError> {
    let records_deleted =
        delete_db_user(username).map_err(|err| DBError::InternalServerError(err))?;

    if records_deleted > 1 {
        panic!(
            "Multiple records deleted!! 1 should have been deleted, actual: {}",
            records_deleted
        );
    }

    Ok(())
}

pub enum DBError {
    NotFound(String),
    InternalServerError(diesel::result::Error),
}

// Implement std::fmt::Display for AppError
impl fmt::Display for DBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DBError::NotFound(_data) => {
                write!(f, "User not found!")
            }
            DBError::InternalServerError(_diesel_error) => {
                write!(f, "There was an error on our side :(")
            }
        }
    }
}

// Implement std::fmt::Debug for AppError
impl fmt::Debug for DBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DBError::NotFound(data) => {
                write!(f, "Data could not be found: {}", data)
            }
            DBError::InternalServerError(diesel_error) => {
                write!(f, "Diesel error: {}", diesel_error)
            }
        }
    }
}

#[cfg(test)]
pub mod test_db_helpers {
    use crate::{
        auth::UserInfo,
        db::db_helper::{
            delete_user, does_user_exist, find_user_by_username, get_pass_hash_for_username,
        },
    };

    use super::create_user;

    #[test]
    fn test_user_process() {
        let user_info = UserInfo {
            first_name: String::from("foo"),
            last_name: String::from("bar"),
            username: String::from("foobar2"),
            pass_hash: String::from("supersecretpassword"),
        };

        // Create

        let created_user = create_user(user_info.clone()).expect("Error getting user");

        assert_eq!(created_user.first_name, user_info.first_name);
        assert_eq!(created_user.last_name, user_info.last_name);
        assert_eq!(created_user.username, user_info.username);

        // Test if user exists
        let user_exists =
            does_user_exist(&created_user.username).expect("Error searching for user");

        assert!(user_exists);

        // Verify password hash is retrieved correctly
        let pass_hash = get_pass_hash_for_username(&created_user.username)
            .expect("Error getting password hash");

        assert_eq!(pass_hash, user_info.pass_hash);

        // Search for user by username
        let user_response =
            find_user_by_username(&user_info.username).expect("Error searching for user");

        assert!(user_response.is_some());

        let user_response = user_response.unwrap();

        assert_eq!(user_response.first_name, user_info.first_name);
        assert_eq!(user_response.last_name, user_info.last_name);
        assert_eq!(user_response.username, user_info.username);

        // Delete user
        delete_user(&user_info.username).expect("Error deleting records");

        // Verify the user does not exist
        let user_exists =
            does_user_exist(&created_user.username).expect("Error searching for user");

        assert!(!user_exists);

        // Search for user by username
        let user_response =
            find_user_by_username(&user_info.username).expect("Error searching for user");

        assert!(user_response.is_none());
    }
}
