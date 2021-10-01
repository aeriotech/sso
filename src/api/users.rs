use std::vec::Vec;
use std::str;
use rocket::serde::json::{Json};
use rocket::serde::{Serialize, Deserialize};
use rocket::form::Form;
use rocket::response::Redirect;
use argon2::{self, Config, ThreadMode, Variant, Version};
use rand::Rng;
use rocket::http::{Status, ContentType};
use std::time::{SystemTime, UNIX_EPOCH};
use std::clone::Clone;

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

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
const ACCESS_TOKEN_LENGTH: usize = 128;

//Duration in seconds (one month)
const ACCESS_TOKEN_DURATION: u64 = 60*60*24*30;

#[database("users_db")]
struct UsersDBConnection(postgres::Client);

#[derive(Serialize, Deserialize, FromForm)]
#[serde(crate = "rocket::serde")]
struct UserIn{
    username: Option<String>,
    password: Option<String>
}

#[derive(Serialize, Deserialize, FromForm, Clone)]
#[serde(crate = "rocket::serde")]
struct AuthenticationRequest{
    username: Option<String>,
    password: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
    response_type: Option<String>,
}

#[derive(Serialize, Deserialize, FromForm)]
#[serde(crate = "rocket::serde")]
struct AuthenticationResponse{
    access_token: Option<String>,
    refresh_token: Option<String>,
    expiration: Option<u64>,
    error_code: Option<u16>,
    error: Option<String>,
    success: bool
}

fn random_bytes() -> String {
    (0..ACCESS_TOKEN_LENGTH)
        .map(|_| {
            let idx = rand::thread_rng().gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn random_bytes_l(len: u32) -> String {
    (0..len)
        .map(|_| {
            let idx = rand::thread_rng().gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
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
    let salt = random_bytes_l(32);
    let password = argon2::hash_encoded(user.password.unwrap().as_bytes(), &salt.as_bytes(), &ARGON_CONFIG).unwrap();

    let user_id = random_bytes();

    let rows_updated = conn.execute("INSERT INTO users (id, username, password, salt) VALUES ($1, $2, $3, $4)", &[&user_id, &username, &password, &salt]).unwrap();

    return if rows_updated == 1 { 0 } else { 2 };
}

fn user_by_name_exists(conn: &mut postgres::Client, input: &String) -> u8{
    let result = conn.query_one("SELECT username FROM users WHERE username = $1", &[input]);
    match result {
        Ok(row) => return if row.is_empty() { 0 } else { 1 },
        Err(_e) => return 0
    }
}

fn get_access_token(conn: &mut postgres::Client, request: &AuthenticationRequest) -> AuthenticationResponse{
    let username: &String = request.username.as_ref().unwrap();
    let password_in: &String = request.password.as_ref().unwrap();

    let user_info = conn.query_one("SELECT password, id FROM users WHERE username=$1", &[username]);

    if user_info.is_err() {
        return AuthenticationResponse{
            access_token: None,
            refresh_token: None,
            expiration: None,
            success: false,
            error_code: Some(401),
            error: Some(String::from("401; invalid credentials")),
        };
    }

    let user_info_raw = user_info.unwrap();

    let password: String = user_info_raw.get(0);
    let user_id: String = user_info_raw.get(1);

    let client_info = conn.query_one("SELECT client_secret FROM clients WHERE client_id = $1", &[&request.client_id]);
    if client_info.is_err() {
        return AuthenticationResponse{
            access_token: None,
            refresh_token: None,
            expiration: None,
            success: false,
            error_code: Some(500),
            error: Some(String::from("500; internal server error")),
        };
    }

    let client_secret: String = client_info.unwrap().get(0);
    let client_secret_in: &String = request.client_secret.as_ref().unwrap();
    if &client_secret != client_secret_in{
        return AuthenticationResponse{
            access_token: None,
            refresh_token: None,
            expiration: None,
            success: false,
            error_code: Some(401),
            error: Some(String::from("401; invalid credentials")),
        };
    }

    if argon2::verify_encoded(&password, &password_in.as_bytes()).unwrap() { 
        let access_token: String = random_bytes();
        let refresh_token: String = random_bytes();

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let seconds_since: String = (since_the_epoch.as_secs() + ACCESS_TOKEN_DURATION).to_string();

        // !TODO: Query parameters don't work inside DO statements. Maybe try temporary variales https://stackoverflow.com/questions/18811265/sql-creating-temporary-variables
        let rows_updated = conn.execute(
            "DO
            $do$
            BEGIN
               IF EXISTS (SELECT FROM tokens WHERE user_id=:1 AND client_id=:2) THEN
                  UPDATE tokens SET access_token=:3, access_token_expire=:5 WHERE user_id=:1 AND client_id=:2;
               ELSE
                  INSERT INTO tokens VALUES (:2, :1, :3, :4, :5);
               END IF;
            END
            $do$", &[&user_id, &request.client_id, &access_token, &refresh_token, &seconds_since]);

        if rows_updated.is_err() {
            return AuthenticationResponse{
                access_token: None,
                refresh_token: None,
                expiration: None,
                success: false,
                error_code: Some(500),
                error: Some(String::from("500; internal server error")),
            };
        }

        if rows_updated.unwrap() == 1{
            return AuthenticationResponse{
                access_token: Some(access_token),
                refresh_token: Some(refresh_token),
                expiration: Some(since_the_epoch.as_secs() + ACCESS_TOKEN_DURATION),
                error: None,
                error_code: None,
                success: true,
            };
        }else{ 
            return AuthenticationResponse{
                access_token: None,
                refresh_token: None,
                expiration: None,
                success: false,
                error_code: Some(500),
                error: Some(String::from("500; internal server error")),
            };
        }
    }else{ 
        return AuthenticationResponse{
            access_token: None,
            refresh_token: None,
            expiration: None,
            success: false,
            error_code: Some(401),
            error: Some(String::from("401; invalid credentials")),
        };
    }
}

fn is_user_authentcated(conn: &mut postgres::Client, access_token: &String, client_id: &String, user_id: &String) -> (u16, String){
    let response_raw = conn.query_one("SELECT (access_token_expire) FROM tokens WHERE access_token=$1 AND client_id=$2 AND user_id=$3", &[access_token, client_id, user_id]);

    if response_raw.is_err() {
        return (401, String::from("{\"success\": false, \"error_code\": 401, \"error\": \"Invalid credentials\"}"));
    }

    let response = response_raw.unwrap();
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let expire_time_str: String = response.get(4);
    let expire_time = expire_time_str.parse::<u64>();

    if expire_time.is_err(){
        return (401, String::from("{\"success\": false, \"error_code\": 500, \"error\": \"Internal server error\"}"));
    }

    if expire_time.unwrap() < since_the_epoch.as_secs(){
        return (401, String::from("{\"success\": false, \"error_code\": 401, \"error\": \"Token expired\"}"));
    }else{
        return (200, String::from("{\"success\": true}"))
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

#[post("/authenticate", format = "json", data = "<input>", rank = 1)]
async fn authenticate(conn: UsersDBConnection, input: Json<AuthenticationRequest>) -> (Status, (ContentType, String)) {
    let req = input.into_inner();
    if req.username.is_none() || req.password.is_none() {
        return (Status::Unauthorized, (ContentType::JSON, String::from("{\"errorCode\": 401, \"message\": \"invalid credentials\"}")));
    }
    
    if req.response_type.is_none(){
        return (Status::BadRequest, (ContentType::JSON, String::from("{\"errorCode\": 400, \"message\": \"invalid request type\"}")));
    }

    let req_clone: AuthenticationRequest = req.clone();
    let response_type = req.response_type.unwrap();
    if response_type == "code"{
        let req_clone_v2 = req_clone.clone();
        let res = conn.run(move |c| {
            return get_access_token(c, &req_clone_v2);
        }).await;

        let res_json: String = rocket::serde::json::serde_json::to_string_pretty(&res).unwrap();
        return (Status::from_code(res.error_code.unwrap()).unwrap(), (ContentType::JSON, res_json));
    }else if response_type == "refresh"{
        return (Status::NotImplemented, (ContentType::JSON, String::from("{\"error)error_code\": \"501\", \"error\": \"Not Implemented\"}")));
    }else{
        return (Status::BadRequest, (ContentType::JSON, String::from("{\"errorCode\": 400, \"message\": \"invalid request type\"}")));
    }
}

#[post("/test?<access_token>&<client_id>&<user_id>", rank = 1)]
async fn test_endpoint(conn: UsersDBConnection, access_token: String, client_id: String, user_id: String) -> (Status, (ContentType, String)){
    let res = conn.run(move |c| {
        return is_user_authentcated(c, &access_token, &client_id, &user_id);
    }).await;

    return (Status::from_code(res.0).unwrap(), (ContentType::JSON, res.1));
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Users", |rocket| async {
        rocket.mount("/api/users", routes![get, new, new_form, authenticate, test_endpoint]).attach(UsersDBConnection::fairing())
    })
}