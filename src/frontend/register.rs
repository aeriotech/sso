use std::collections::HashMap;
use rocket_dyn_templates::{Template};

#[get("/?<redirect_uri>")]
fn register(redirect_uri: String) -> Template {
    let mut context = HashMap::new();

    context.insert("redirect_uri", &redirect_uri);

    return Template::render("register", context);
}

pub fn stage() -> Vec<rocket::Route> {
    routes![register]
}