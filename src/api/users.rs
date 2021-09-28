use std::vec::Vec;
use std::str;
use rocket::serde::uuid::Uuid;
use rocket::serde::json::{Json};
use rocket::serde::{Serialize, Deserialize};
use rocket::form::Form;
use rocket::response::Redirect;
use argon2::{self, Config, ThreadMode, Variant, Version};
use rand::Rng;

use rocket_sync_db_pools::{database, postgres};

const ARGON_CONFIG: Config = Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 65536,
    time_cost: 10,
    lanes: 4,
    thread_mode: ThreadMode::Parallel,
    secret: &[],
    ad: &[],
    hash_length: 32
};

#[database("users_db")]
struct UsersDBConnection(postgres::Client);

#[derive(Serialize, Deserialize, FromForm)]
#[serde(crate = "rocket::serde")]
struct UserIn{
    username: Option<String>,
    password: Option<String>
}

struct PasswordContainer{
    password: String
}

fn load_users(conn: &mut postgres::Client) -> Vec<UserIn> {
    let rows = conn.query("SELECT * FROM users", &[]).unwrap();
    let mut users = Vec::with_capacity(rows.len());

    for row in rows{
        users.push(UserIn { username: row.get("username"), password: row.get("password") });
    }

    return users;
}

fn create_user(conn: &mut postgres::Client, user: UserIn) -> u8{
    if user.username.is_none() || user.password.is_none() { 
        return 1;
    }

    let username = user.username.unwrap();
    if user_by_name_exists(conn, &username) != 0{
        return 1;
    }
    let salt = rand::thread_rng().gen::<[u8; 32]>();
    let password = argon2::hash_encoded(user.password.unwrap().as_bytes(), &salt, &ARGON_CONFIG).unwrap();
    let salt_string = str::from_utf8(&salt).unwrap();

    let uuid = Uuid::new_v4();

    let rows_updated = conn.execute("INSERT INTO users (id, username, password, salt) VALUES ($1, $2, $3, $4)", &[&uuid, &username, &password, &salt_string]).unwrap();

    return if rows_updated == 1 { 0 } else { 2 };
}

fn user_by_name_exists(conn: &mut postgres::Client, input: &String) -> u8{
    let result = conn.query_one("SELECT username FROM users WHERE username = $1", &[input]);
    match result {
        Ok(row) => return if row.is_empty() { 0 } else { 1 },
        Err(_e) => return 0
    }
}

fn get_access_token(conn: &mut postgres::Client, username: &String, password: &String) -> Result<Vec<u8>, u8>{
    let access_token: Vec<u8> = (0..127).map(|_| { rand::random::<u8>() }).collect();

    let password_hash = conn.query_one("SELECT (password) FROM users WHERE username=$1", &[&username]);

    if password_hash.is_err() {
        return Err(1);
    }

    let pwd = PasswordContainer {
        password: password_hash.unwrap().get(0)
    };

    if argon2::verify_encoded(&pwd.password, &password.as_bytes()).unwrap() { 
        let rows_updated = conn.execute("UPDATE users SET access_token=$1 WHERE username=$2", &[&access_token, &username]);

        if rows_updated.is_err() {
            return Err(2);
        }

        if rows_updated.unwrap() == 1{
            return Ok(access_token);
        }else{ 
            return Err(2);
        }
    }else{ 
        return Err(1);
    }
}

#[get("/")]
async fn get(conn: UsersDBConnection) -> Json<Vec<UserIn>> {
    Json(conn.run(|c| load_users(c)).await)
}

#[post("/new", format = "json", data = "<input>", rank = 1)]
async fn new(conn: UsersDBConnection, input: Json<UserIn>) -> &'static str {
    let status = conn.run(|c| create_user(c, input.into_inner())).await;

    match status {
        0 => return "201; success",
        1 => return "403; username taken",
        _ => return "500; server error"
    }
}

#[post("/new", data = "<input>", rank = 2)]
async fn new_form(conn: UsersDBConnection, input: Form<UserIn>) -> Redirect {
    let status = conn.run(|c| create_user(c, input.into_inner())).await;

    match status {
        0 => Redirect::to(uri!("/")),
        1 => Redirect::to(uri!("/login?error_code=1")),
        _ => Redirect::to(uri!("/login?error_code=2"))
    }
}

#[post("/login", format = "json", data = "<input>", rank = 1)]
async fn login(conn: UsersDBConnection, input: Json<UserIn>) -> String {
    let user = input.into_inner();
    if user.username.is_none() || user.password.is_none() {
        return String::from("401; invalid username or password");
    }
    let status = conn.run(|c| get_access_token(c, &user.username.unwrap(), &user.password.unwrap())).await;

    if status.is_err() {
        return match status.err() {
            Some(1) => String::from("401; invalid username or password"),
            _ => String::from("500; internal server error")
        }
    }else{
        let token = status.ok();
        let token_str = String::from_utf8(token.unwrap()).unwrap();
        return token_str;
    }
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Users", |rocket| async {
        rocket.mount("/api/users", routes![get, new, new_form, login]).attach(UsersDBConnection::fairing())
    })
}