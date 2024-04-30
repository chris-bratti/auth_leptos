use std::env;

use dotenvy::dotenv;

pub fn get_env_variable(variable: &str) -> Option<String> {
    match std::env::var(variable) {
        Ok(env_variable) => Some(env_variable.trim().to_string()),
        Err(_) => {
            dotenv().ok();

            match env::var(variable) {
                Ok(var_from_file) => Some(var_from_file.trim().to_string()),
                Err(_) => None,
            }
        }
    }
}

#[cfg(test)]
pub mod test_helpers {
    use crate::server::helpers::get_env_variable;

    #[test]
    pub fn test_env_variables() {
        // Ensures the necessary env variables are present
        assert!(get_env_variable("FROM_EMAIL").is_some());
        assert!(get_env_variable("SMTP_KEY").is_some());
        assert!(get_env_variable("ENCRYPTION_KEY").is_some());
    }
}
