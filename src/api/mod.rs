pub mod users;
pub mod clients;

pub fn stage() -> rocket::fairing::AdHoc {
    return rocket::fairing::AdHoc::on_ignite("API", |rocket| async {
        rocket.mount("/api/users", users::stage())
            .mount("/api/clients", clients::stage())
    });
}