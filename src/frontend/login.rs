use std::collections::HashMap;
use rocket_dyn_templates::{Template};

#[get("/?<errorCode..>", rank = 1)]
fn login(errorCode: u8) -> Template{
    let mut context = HashMap::new();

    let message = match errorCode {
        0 => "",
        1 => "Username taken",
        _ => "Internal server error, please try again later."
    };

    context.insert("message", message);

    return Template::render("login", context);
}

#[get("/", rank = 2)]
fn login_no_param() -> Template{
    let mut context = HashMap::new();

    context.insert("message", "");

    return Template::render("login", context);
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Login", |rocket| async {
        rocket.mount("/login", routes![login, login_no_param])
    })
}