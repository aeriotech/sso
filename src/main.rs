#[macro_use] extern crate rocket;

use rocket::fs::FileServer;

mod api;
mod frontend;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(api::stage())
        .attach(frontend::stage())
        .mount("/static", FileServer::from("static/"))
}
