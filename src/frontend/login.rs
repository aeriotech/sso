use std::collections::HashMap;
use rocket_dyn_templates::{Template};
use urlencoding::encode;

#[get("/?<client_id>&<scope>&<redirect_uri>", rank = 2)]
fn login(client_id: String, scope: String, redirect_uri: String) -> Template{
    let mut context = HashMap::new();

    let client_id_encoded = encode(client_id.as_ref());
    let scope_encoded = encode(scope.as_ref());
    let redirect_uri_encoded = encode(redirect_uri.as_ref());

    context.insert("client_id", client_id_encoded.as_ref());
    context.insert("scope", scope_encoded.as_ref());
    context.insert("redirect_uri", redirect_uri_encoded.as_ref());

    return Template::render("login", context);
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Login", |rocket| async {
        rocket.mount("/login", routes![login])
    })
}