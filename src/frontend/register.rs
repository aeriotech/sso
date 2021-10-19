use std::collections::HashMap;
use rocket_dyn_templates::{Template};
use urlencoding::encode;

#[get("/?<redirect_uri>")]
fn register(redirect_uri: String) -> Template {
    let mut context = HashMap::new();

    let redirect_uri_encoded = encode(redirect_uri.as_ref());

    context.insert("redirect_uri", redirect_uri_encoded.as_ref());

    return Template::render("register", context);
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Register", |rocket| async {
        rocket.mount("/register", routes![register])
    })
}