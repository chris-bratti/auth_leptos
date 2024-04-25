// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Int4,
        first_name -> Text,
        last_name -> Text,
        username -> Text,
        pass_hash -> Text,
        active_sessions -> Nullable<Array<Nullable<Text>>>,
    }
}
