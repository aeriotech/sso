pub mod users;
pub mod clients;

pub fn stage() -> rocket::fairing::AdHoc {
    return rocket::fairing::AdHoc::on_ignite("API", |rocket| async {
        rocket.attach(users::stage()).attach(clients::stage())
    });
}