use crate::{auth::*, User};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

static PASSWORD_PATTERN: &str =
    "^.*(?=.{8,}).*(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@!:#$^;%&?]).+$";

#[derive(Clone)]
struct UserContext {
    pub user_signal: (ReadSignal<User>, WriteSignal<User>),
}

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
                    <Route
                        path="/user"
                        view= || view! {
                            <UserVerificationWrapper>
                                <UserProfile/>
                            </UserVerificationWrapper>
                        }/>
                    <Route path="/signup" view=SignUp/>
                    <Route path="/login" view=Auth/>
                    <Route path="/forgotpassword" view=ForgotPassword/>
                    <Route path="/reset/:generated_id" view=ResetPassword/>
                    <Route path="/verify/:generated_id" view=Verify/>
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
fn Verify() -> impl IntoView {
    let params = use_params_map();
    let generated_id =
        move || params.with(|params| params.get("generated_id").cloned().unwrap_or_default());

    let verify_user = create_server_action::<VerifyUser>();
    let validation_result = verify_user.value();
    let pending = verify_user.pending();

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            {move || {
                if !pending() {
                    if validation_result.get().is_some() {
                        view! {
                            <h1>There was an error verifying your account</h1>
                            <p>Your verification link could have expired. Try resending</p>
                        }
                            .into_view()
                    } else {
                        view! {
                            <ActionForm action=verify_user>
                                <div class="mb-3">
                                    <label class="form-label">
                                        "Username"
                                        <input
                                            class="form-control"
                                            type="text"
                                            name="username"
                                            required=true
                                        />
                                    </label>
                                </div>
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="verification_token"
                                    value=generated_id()
                                />
                                <input
                                    class="btn btn-primary"
                                    type="submit"
                                    value="Request Password Reset"
                                />
                            </ActionForm>
                        }
                            .into_view()
                    }
                } else {
                    view! { <h1>Verifying...</h1> }.into_view()
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
pub fn LoggedIn(children: ChildrenFn) -> impl IntoView {
    let user_result = create_resource(|| (), |_| async move { get_user_from_session().await });
    let verification_result = create_resource(
        move || user_result(),
        |user| async move { check_user_verification(user.unwrap().unwrap().username).await },
    );
    let children = store_value(children);
    let user_is_logged_in = move || user_result.get().is_some();
    let logged_in_fallback = || view! { <NotLoggedIn/> };
    let verified_fallback = || {
        view! { <NotVerified/> }
    };
    let user_is_verified =
        move || verification_result.get().is_some() && verification_result.get().unwrap().unwrap();
    view! {
        <Suspense fallback=|| {
            view! { <h1>Loading....</h1> }
        }>
            <Show when=user_is_logged_in fallback=logged_in_fallback>
                {{provide_context(UserContext {
                    user_signal: create_signal(user_result.get().unwrap().unwrap()),
                })}}
                <Show when=user_is_verified fallback=verified_fallback>
                    {children.with_value(|children| children())}
                </Show>
            </Show>
        </Suspense>
    }
}

#[component]
pub fn UserVerificationWrapper(children: ChildrenFn) -> impl IntoView {
    let children = store_value(children);
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <LoggedIn>{children.with_value(|children| children())}</LoggedIn>
        </div>
    }
}

#[component]
pub fn UserProfile() -> impl IntoView {
    let (user, _): (ReadSignal<User>, WriteSignal<User>) =
        expect_context::<UserContext>().user_signal;
    let (update_password, set_update_password) = create_signal(false);
    view! {
        {move || {
            if update_password.get() {
                view! { <ChangePassword username = user.get().username/> }.into_view()
            } else {
                view! {
                    // let username = user.username;
                    <button class="btn btn-primary" on:click=move |_| set_update_password(true)>
                        Update Password
                    </button>
                }
                    .into_view()
            }
        }}
    }
}

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

#[component]
fn NotVerified() -> impl IntoView {
    view! {
        <h1>Your email is not verified</h1>
        <p>Please follow the link we sent to your inbox to verify your email!</p>
        <div>
            <A class="btn btn-primary" href="/">
                "Home"
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
