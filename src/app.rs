use crate::{auth::*, User};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

static PASSWORD_PATTERN: &str =
    "^.*(?=.{8,}).*(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@!:#$^;%&?]).+$";

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/auth_leptos.css"/>
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
                    <Route path="/forgotpassword" view=ForgotPassword/>
                    <Route path="/reset/:generated_id" view=ResetPassword/>
                    <Route path="/*any" view=NotFound/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    // Basic homepage
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <h1>"Welcome to Leptos!"</h1>
            <A href="/login" class="btn btn-primary">
                Login
            </A>
            <A href="/signup" class="btn btn-primary">
                Sign Up
            </A>
            <A class="btn btn-primary" href="/user">
                "To user"
            </A>
        </div>
    }
}

#[component]
fn ForgotPassword() -> impl IntoView {
    // TODO: Will need to implement user emails in order for this to be more secure.
    // Currently, you can just request any username with any email and you can reset the password
    // Will require users to provide emails when signing up - could just replace usernames (maybe hash them though?)
    let forgot_password = create_server_action::<RequestPasswordReset>();

    view! {
        <h1>Forgot Password</h1>
        <div style:font-family="sans-serif" style:text-align="center">
            <ActionForm action=forgot_password>
                <div class="mb-3">
                    <label class="form-label">
                        "Username"
                        <input class="form-control" type="text" name="username" required=true/>
                    </label>
                </div>
                <input class="btn btn-primary" type="submit" value="Request Password Reset"/>
            </ActionForm>
        </div>
    }
}

#[component]
fn ResetPassword() -> impl IntoView {
    let params = use_params_map();
    let generated_id =
        move || params.with(|params| params.get("generated_id").cloned().unwrap_or_default());
    let (passwords_match, set_passwords_match) = create_signal(true);
    // Uses the SignUp server function
    let reset_password = create_server_action::<PasswordReset>();
    // Used to fetch any errors returned from the server
    let reset_password_value = reset_password.value();
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <h1>Reset Password</h1>
            <ActionForm
                on:submit=move |ev| {
                    let data = PasswordReset::from_event(&ev);
                    if data.is_err() {
                        ev.prevent_default();
                    } else {
                        let data_values = data.unwrap();
                        if data_values.new_password != data_values.confirm_password {
                            set_passwords_match(false);
                            ev.prevent_default();
                        }
                    }
                }
                action=reset_password
            >
                <div class="mb-3">
                    <label class="form-label">
                        "Username"
                        <input class="form-control" type="text" name="username" required=true/>
                    </label>
                </div>
                <input
                    class="form-control"
                    type="hidden"
                    name="reset_token"
                    value=move || generated_id()
                />
                <div class="mb-3">
                    <label class="form-label">
                        "New Password"
                        <input
                            class="form-control"
                            type="password"
                            name="new_password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                        />
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Confirm New Password"
                        <input
                            class="form-control"
                            type="password"
                            name="confirm_password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                        />
                    </label>
                </div>
                <input class="btn btn-primary" type="submit" value="Update Password"/>
            </ActionForm>
            {move || {
                if !passwords_match.get() {
                    view! { <p>Passwords do not match</p> }.into_view()
                } else {
                    view! {}.into_view()
                }
            }}

            {move || {
                match reset_password_value.get() {
                    Some(response) => {
                        match response {
                            Ok(_) => view! {}.into_view(),
                            Err(server_err) => {
                                view! { <p>{format!("{}", server_err.to_string())}</p> }.into_view()
                            }
                        }
                    }
                    None => view! {}.into_view(),
                }
            }}

        </div>
    }
}

#[component]
fn SignUp() -> impl IntoView {
    // Uses the SignUp server function
    let signup = create_server_action::<SignUp>();
    // Used to fetch any errors returned from the server
    let signup_value = signup.value();
    // Used for client side password validation
    let (passwords_match, set_passwords_match) = create_signal(true);

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <h1>"Create New User"</h1>
            // Form for user sign up, does some client side field validation
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
                        "First Name"
                        <input class="form-control" type="text" name="first_name" required=true/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Last Name"
                        <input class="form-control" type="text" name="last_name" required=true/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Username"
                        <input
                            class="form-control"
                            type="text"
                            name="username"
                            required=true
                            minLength=5
                            maxLength=16
                        />
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Email"
                        <input class="form-control" type="email" name="email" required=true/>
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Password"
                        <input
                            class="form-control"
                            type="password"
                            name="password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                        />
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Password"
                        <input
                            class="form-control"
                            type="password"
                            name="confirm_password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                        />
                    </label>
                    {move || {
                        if !passwords_match.get() {
                            view! { <p>Passwords do not match</p> }.into_view()
                        } else {
                            view! {}.into_view()
                        }
                    }}

                    {move || {
                        match signup_value.get() {
                            Some(response) => {
                                match response {
                                    Ok(_) => view! {}.into_view(),
                                    Err(server_err) => {
                                        view! {
                                            // Displays any errors returned from the server
                                            <p>{format!("{}", server_err.to_string())}</p>
                                        }
                                            .into_view()
                                    }
                                }
                            }
                            None => view! {}.into_view(),
                        }
                    }}

                </div>
                <input class="btn btn-primary" type="submit" value="Sign Up"/>
            </ActionForm>
        </div>
    }
}

#[component]
fn Auth() -> impl IntoView {
    // Uses Login server function
    let login = create_server_action::<Login>();
    // Used to fetch any errors returned from the Login function
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
                                view! {
                                    // Displays any errors returned from the server
                                    <p>{format!("{}", server_err.to_string())}</p>
                                }
                                    .into_view()
                            }
                        }
                    }
                    None => view! {}.into_view(),
                }
            }}

            <A class="btn btn-primary" href="/forgotpassword">
                "Forgot Password?"
            </A>

        </div>
    }
}

#[component]
fn UserPage() -> impl IntoView {
    // Calls server function to retrieve User object from username currently stored in session
    let user_result = create_resource(|| (), |_| async move { get_user_from_session().await });
    let check_verification = create_server_action::<IsUserVerified>();
    let checking_verification = check_verification.pending();
    let loading = user_result.loading();
    let user_signal: RwSignal<Option<User>> = create_rw_signal(None);
    let (update_password, set_update_password) = create_signal(false);
    view! {
        <div style:font-family="sans-serif" style:text-align="center">

            {{
                move || {
                    if loading() {
                        view! { <p>Loading...</p> }.into_view()
                    } else {
                        user_signal
                            .set(
                                match user_result.get() {
                                    Some(user_result) => {
                                        match user_result {
                                            Ok(user) => {
                                                check_verification.dispatch(IsUserVerified{username: user.username.clone()});
                                                Some(user)
                                            },
                                            Err(_err) => None,
                                        }
                                    }
                                    None => None,
                                },
                            );
                        match user_signal.get() {
                            None => view! { <NotLoggedIn/> }.into_view(),
                            Some(user) => {
                                view! {
                                    {move || {
                                        if checking_verification(){
                                            view! { <p>Loading...</p> }.into_view()
                                        }else{
                                            let user_verified = check_verification.value().get().expect("Error verifying").expect("Could not verify user");
                                            view! {
                                                {move|| {
                                                    if user_verified {
                                                        view! {}.into_view()
                                                    }else{
                                                        view! {
                                                            {move || {
                                                                if update_password.get() {
                                                                    view! {
                                                                        // let username = user.username;
                                                                        <p>What ever</p>
                                                                    }
                                                                        .into_view()
                                                                } else{
                                                                    view! {
                                                                        // let username = user.username;
                                                                        <button
                                                                            class="btn btn-primary"
                                                                            on:click=move |_| set_update_password(true)
                                                                        >
                                                                            Update Password
                                                                        </button>
                                                                    }
                                                                        .into_view()
                                                                }
                                                            }}
                                                        }.into_view()
                                                    }
                                                }}

                                            }.into_view()
                                        }
                                    }}
                                }.into_view()

                            }
                        }
                    }
                }
            }}

        </div>
    }
}

/*
view! {
                                                {if verified {
                                                    view! {{move || {
                                                        if update_password.get() {
                                                            view! {
                                                                // let username = user.username;
                                                                <ChangePassword username=user.username.clone()/>
                                                            }
                                                                .into_view()
                                                        } else {
                                                            view! {
                                                                // let username = user.username;
                                                                <button
                                                                    class="btn btn-primary"
                                                                    on:click=move |_| set_update_password(true)
                                                                >
                                                                    Update Password
                                                                </button>
                                                            }
                                                                .into_view()
                                                        }
                                                    }}}.into_view()
                                                }else{
                                                    view! {<NotLoggedIn/>}.into_view()
                                                }}.into_view()
                                            }.into_view() */

#[component]
fn ChangePassword(username: String) -> impl IntoView {
    let update_password = create_server_action::<UpdatePassword>();

    let update_password_value = update_password.value();

    let (passwords_match, set_passwords_match) = create_signal(true);
    let (old_pass_used, set_old_pass_used) = create_signal(false);
    view! {
        <h1>Change Password</h1>
        <div style:font-family="sans-serif" style:text-align="center">
            <ActionForm
                on:submit=move |ev| {
                    let data = UpdatePassword::from_event(&ev);
                    if data.is_err() {
                        ev.prevent_default();
                    } else {
                        let data_values = data.unwrap();
                        if data_values.new_password != data_values.confirm_new_password {
                            set_passwords_match(false);
                            ev.prevent_default();
                        }
                        if data_values.new_password == data_values.current_password {
                            set_old_pass_used(true);
                            ev.prevent_default();
                        }
                    }
                }
                action=update_password
            >
                <input class="form-control" type="hidden" name="username" value=username/>
                <div class="mb-3">
                    <label class="form-label">
                        "Current Password"
                        <input
                            class="form-control"
                            type="password"
                            name="current_password"
                            required=true
                        />
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "New Password"
                        <input
                            class="form-control"
                            type="password"
                            name="new_password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                        />
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        "Confirm New Password"
                        <input
                            class="form-control"
                            type="password"
                            name="confirm_new_password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                        />
                    </label>
                </div>
                <input class="btn btn-primary" type="submit" value="Update Password"/>
            </ActionForm>
            {move || {
                if !passwords_match.get() {
                    view! { <p>Passwords do not match</p> }.into_view()
                } else {
                    view! {}.into_view()
                }
            }}

            {move || {
                if old_pass_used.get() {
                    view! { <p>New password cannot match current password</p> }.into_view()
                } else {
                    view! {}.into_view()
                }
            }}

            {move || {
                match update_password_value.get() {
                    Some(response) => {
                        match response {
                            Ok(_) => view! {}.into_view(),
                            Err(server_err) => {
                                view! { <p>{format!("{}", server_err.to_string())}</p> }.into_view()
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
fn NotLoggedIn() -> impl IntoView {
    view! {
        <h1>"You need to be logged in to view this page"</h1>
        <div>
            <A class="btn btn-primary" href="/">
                "Home"
            </A>
        </div>

        <div>
            <A class="btn btn-primary" href="/login">
                "Login"
            </A>
        </div>
        <div>
            <A class="btn btn-primary" href="/signup">
                "Signup"
            </A>
        </div>
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
