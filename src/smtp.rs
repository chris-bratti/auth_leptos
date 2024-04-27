use lettre::message::header::{self, ContentType};
use lettre::message::{MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use maud::html;

pub fn generate_reset_email_body(username: &String, reset_token: &String) -> String {
    // The recipient's name. We might obtain this from a form or their email address.
    // Create the html we want to send.
    let reset_link = format!("http://localhost:3000/{}", reset_token);
    html! {
        head {
            title { "Password Reset" }
            style type="text/css" {
                "h2, h4 { font-family: Arial, Helvetica, sans-serif; }"
            }
        }
        div style="display: flex; flex-direction: column; align-items: center;" {
            h2 { "Password Reset" }
            // Substitute in the name of our recipient.
            p { "Hello " (username) "," }
            p { "We got received a request to reset your password."}
            p {
                "To reset your password, click the "
                a href=(reset_link) { "reset link" }
                ""
            }
            p { "If you did not request this reset, please contact us."}
        }
    }
    .into_string()
}

pub fn send_reset_email(email: &String, email_body: String, first_name: &String) {
    let email = Message::builder()
        .from("NoBody <nobody@domain.tld>".parse().unwrap())
        .to(format!("{} <{}>", first_name, email).parse().unwrap())
        .subject("Reset Your Password")
        .multipart(
            MultiPart::alternative() // This is composed of two parts.
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(String::from(
                            "There was an issue resetting your password, please contact us.",
                        )), // Every message should have a plain text fallback.
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(email_body),
                ),
        )
        .expect("failed to build email");

    let creds = Credentials::new("smtp_username".to_owned(), "smtp_password".to_owned());

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
