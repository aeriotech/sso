#[macro_use] extern crate rocket;

mod api;
mod frontend;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(api::stage())
        .attach(frontend::stage())
}
