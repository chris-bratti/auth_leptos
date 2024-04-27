#[cfg(feature = "ssr")]
use dotenvy::dotenv;
#[cfg(feature = "ssr")]
use lettre::message::header::{self};
#[cfg(feature = "ssr")]
use lettre::message::{MultiPart, SinglePart};
#[cfg(feature = "ssr")]
use lettre::transport::smtp::authentication::Credentials;
#[cfg(feature = "ssr")]
use lettre::{Message, SmtpTransport, Transport};
#[cfg(feature = "ssr")]
use maud::html;
#[cfg(feature = "ssr")]
use std::env;

#[cfg(feature = "ssr")]
pub fn generate_reset_email_body(reset_token: &String, first_name: &String) -> String {
    // The recipient's name. We might obtain this from a form or their email address.
    // Create the html we want to send.
    let reset_link = format!("http://localhost:3000/reset/{}", reset_token);

    // HTML shamelessly generated with Chat-GPT. Adapted to a maud template
    html! {
        head {
            title {"Password Reset"}
            style type="text/css" {
                "body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: #333;
                }
                p {
                    margin-bottom: 20px;
                    color: #666;
                }
                .btn {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #FEFEFE;
                    text-decoration: none;
                    border-radius: 4px;
                }
                .btn:hover {
                    background-color: #0056b3;
                }"
            }
        }
        body{
            div class="container" {
                h1 {"Password Reset"}
                p{ "Hello, " (first_name) }
                p{"You have requested to reset your password. Please click the button below to proceed"}
                a class="btn" href={ (reset_link) } {
                    "Reset Password"
                }
                p{"If you did not request this, please contact us."}

            }
        }
    }.into_string()
}

#[cfg(feature = "ssr")]
pub fn send_email(email: &String, email_body: String, first_name: &String) {
    dotenv().ok();

    let from_email = env::var("FROM_EMAIL").expect("FROM_EMAIL must be set");
    let smtp_key = env::var("KEY").expect("KEY must be set");
    let email = Message::builder()
        .from(format!("Leptos Auth <{from_email}>").parse().unwrap())
        .to(format!("{first_name} <{email}>").parse().unwrap())
        .subject("Reset Your Password")
        .multipart(
            MultiPart::alternative() // This is composed of two parts.
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(String::from(
                            "There was an error formatting your email, please contact us.",
                        )), // Every message should have a plain text fallback.
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(email_body),
                ),
        )
        .expect("failed to build email");

    let creds = Credentials::new(from_email, smtp_key);

    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {e:?}"),
    }
}
