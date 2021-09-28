#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Index", |rocket| async {
        rocket.mount("/", routes![index])
    })
}