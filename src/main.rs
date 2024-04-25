#[cfg(feature = "ssr")]
use actix_web::cookie::Key;

#[cfg(feature = "ssr")]
#[actix_web::main]

async fn main() -> std::io::Result<()> {
    use actix_files::Files;
    use actix_web::*;
    use dAIly::app::*;
    use leptos::*;
    use leptos_actix::{generate_route_list, LeptosRoutes};

    use actix_identity::IdentityMiddleware;
    use actix_session::{storage::RedisSessionStore, SessionMiddleware};

    let conf = get_configuration(None).await.unwrap();
    let addr = conf.leptos_options.site_addr;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);
    println!("listening on http://{}", &addr);

    let secret_key = get_secret_key();
    let redis_connection_string = "redis://127.0.0.1:6379";
    let store = RedisSessionStore::new(redis_connection_string)
        .await
        .unwrap();

    HttpServer::new(move || {
        let leptos_options = &conf.leptos_options;
        let site_root = &leptos_options.site_root;

        App::new()
            // serve JS/WASM/CSS from `pkg`
            .service(Files::new("/pkg", format!("{site_root}/pkg")))
            // serve other assets from the `assets` directory
            .service(Files::new("/assets", site_root))
            // serve the favicon from /favicon.ico
            .service(favicon)
            .leptos_routes(leptos_options.to_owned(), routes.to_owned(), App)
            .app_data(web::Data::new(leptos_options.to_owned()))
            .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(store.clone(), secret_key.clone()))
        //.wrap(middleware::Compress::default())
    })
    .bind(&addr)?
    .run()
    .await
}

#[cfg(feature = "ssr")]
fn get_secret_key() -> Key {
    return Key::generate();
}

#[cfg(feature = "ssr")]
#[actix_web::get("favicon.ico")]
async fn favicon(
    leptos_options: actix_web::web::Data<leptos::LeptosOptions>,
) -> actix_web::Result<actix_files::NamedFile> {
    let leptos_options = leptos_options.into_inner();
    let site_root = &leptos_options.site_root;
    Ok(actix_files::NamedFile::open(format!(
        "{site_root}/favicon.ico"
    ))?)
}

#[cfg(not(any(feature = "ssr", feature = "csr")))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
    // see optional feature `csr` instead
}

#[cfg(all(not(feature = "ssr"), feature = "csr"))]
pub fn main() {
    // a client-side main function is required for using `trunk serve`
    // prefer using `cargo leptos serve` instead
    // to run: `trunk serve --open --features csr`
    use dAIly::app::*;

    console_error_panic_hook::set_once();

    leptos::mount_to_body(App);
}
