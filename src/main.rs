#[macro_use] extern crate rocket;

use rocket::fs::FileServer;

mod api;
mod frontend;
mod db;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(api::stage())
        .attach(frontend::stage())
        .attach(db::stage())
        .mount("/static", FileServer::from("static/"))
}
