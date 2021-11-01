use rocket_sync_db_pools::{database, postgres};

#[database("users_db")]
pub struct UsersDBConnection(postgres::Client);

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Login", |rocket| async {
        rocket.attach(UsersDBConnection::fairing())
    })
}