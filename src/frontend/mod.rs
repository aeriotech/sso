mod login;
mod register;

use rocket_dyn_templates::{Template};

pub fn stage() -> rocket::fairing::AdHoc {
    return rocket::fairing::AdHoc::on_ignite("Frontend", |rocket| async {
        rocket.attach(Template::fairing())
            .attach(login::stage())
            .attach(register::stage())
    });
}