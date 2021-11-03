#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

pub fn stage() -> Vec<rocket::Route> {
    routes![index]
}