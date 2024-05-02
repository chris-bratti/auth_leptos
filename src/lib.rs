use serde::{Deserialize, Serialize};

pub mod app;
pub mod auth;
#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub mod server;
pub mod smtp;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use app::*;
    use leptos::*;

    console_error_panic_hook::set_once();

    mount_to_body(App);
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
}
