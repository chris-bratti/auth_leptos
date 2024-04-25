use crate::auth::*;
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/dAIly.css"/>
        <Stylesheet
            id="boostrap"
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        />

        // sets the document title
        <Title text="Welcome to Leptos"/>

        // content for this welcome page
        <Router>
            <main>
                <Routes>
                    <Route path="" view=HomePage/>
                    <Route path="/user" view=UserPage/>
                    <Route path="/signup" view=SignUp/>
                    <Route path="/login" view=Auth/>
                    <Route path="/*any" view=NotFound/>
                </Routes>
            </main>
        </Router>
    }
}

/// Renders the home page of your application.
#[component]
fn HomePage() -> impl IntoView {
    // Creates a reactive value to update the button

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <h1>"Welcome to Leptos!"</h1>
            <A href="/login" class="btn btn-primary">
                Login
            </A>
            <A href="/signup" class="btn btn-primary">
                Sign Up
            </A>
        </div>
    }
}

#[component]
fn SignUp() -> impl IntoView {
    let signup = create_server_action::<SignUp>();

    let (passwords_match, set_passwords_match) = create_signal(true);

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <h1>"Create New User"</h1>

            <ActionForm
                on:submit=move |ev| {
                    let data = SignUp::from_event(&ev);
                    if data.is_err() {
                        ev.prevent_default();
                    } else {
                        let data_values = data.unwrap();
                        if data_values.password != data_values.confirm_password {
                            set_passwords_match(false);
                            ev.prevent_default();
                        }
                    }
                }

                action=signup
            >
                <div class="mb-3">
                    <label class="form-label">
                        "First Name" <input class="form-control" type="text" name="first_name"/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Last Name" <input class="form-control" type="text" name="last_name"/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Username" <input class="form-control" type="text" name="username"/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Password" <input class="form-control" type="password" name="password"/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Password"
                        <input class="form-control" type="password" name="confirm_password"/>
                    </label>
                    {move || {
                        if !passwords_match.get() {
                            view! { <p>Passwords do not match</p> }.into_view()
                        } else {
                            view! {}.into_view()
                        }
                    }}

                </div>
                <input class="btn btn-primary" type="submit" value="Login"/>
            </ActionForm>
        </div>
    }
}

#[component]
fn Auth() -> impl IntoView {
    let login = create_server_action::<Login>();

    let login_value = login.value();

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <h1>"Welcome to Leptos!"</h1>

            <ActionForm action=login>
                <div class="mb-3">
                    <label class="form-label">
                        "Username" <input class="form-control" type="text" name="username"/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Password" <input class="form-control" type="password" name="password"/>
                    </label>
                </div>
                <input class="btn btn-primary" type="submit" value="Login"/>
            </ActionForm>

            {move || {
                match login_value.get() {
                    Some(response) => {
                        match response {
                            Ok(_) => view! {}.into_view(),
                            Err(server_err) => {
                                view! { <p>{format!("{server_err}")}</p> }.into_view()
                            }
                        }
                    }
                    None => view! {}.into_view(),
                }
            }}

            <A class="btn btn-primary" href="/user">
                "To user"
            </A>
        </div>
    }
}

#[component]
fn UserPage() -> impl IntoView {
    let user = create_resource(|| (), |_| async move { get_user().await });
    let loading = user.loading();
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            {{
                move || {
                    if loading() {
                        view! { <p>Loading...</p> }.into_view()
                    } else {
                        match user.get() {
                            None => {
                                view! { <NotLoggedIn/> }
                            }
                            Some(data) => {
                                {
                                    match data {
                                        Ok(user_name) => {
                                            view! { <h1>Welcome {user_name} !</h1> }.into_view()
                                        }
                                        Err(_) => {
                                            view! { <NotLoggedIn/> }
                                        }
                                    }
                                }
                                    .into_view()
                            }
                        }
                    }
                }
            }}
            </div>
    }
}

#[component]
fn NotLoggedIn() -> impl IntoView {
    view! {
        <h1>"You need to be logged in to view this page"</h1>
        <A class="btn btn-primary" href="/">
            "Home"
        </A>
    }
}

/// 404 - Not Found
#[component]
fn NotFound() -> impl IntoView {
    // set an HTTP status code 404
    // this is feature gated because it can only be done during
    // initial server-side rendering
    // if you navigate to the 404 page subsequently, the status
    // code will not be set because there is not a new HTTP request
    // to the server
    #[cfg(feature = "ssr")]
    {
        // this can be done inline because it's synchronous
        // if it were async, we'd use a server function
        let resp = expect_context::<leptos_actix::ResponseOptions>();
        resp.set_status(actix_web::http::StatusCode::NOT_FOUND);
    }

    view! { <h1>"Not Found"</h1> }
}
