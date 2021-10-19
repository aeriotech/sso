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
    password: Option<String>,
    email: Option<String>
}

#[derive(Serialize, Deserialize, FromForm, Clone)]
#[serde(crate = "rocket::serde")]
struct AuthenticationRequest{
    username: Option<String>,
    password: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
    response_type: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize, Deserialize, FromForm)]
#[serde(crate = "rocket::serde")]
struct AuthenticationResponse{
    access_token: Option<String>,
    refresh_token: Option<String>,
    user_id: Option<String>,
    expiration: Option<u64>,
    status_code: Option<u16>,
    error: Option<String>,
    success: bool
}

#[derive(Serialize, Deserialize, FromForm)]
#[serde(crate = "rocket::serde")]
struct TestRequest{
    user_id: Option<String>,
    access_token: Option<String>,
    client_id: Option<String>
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

// Returns status code (u8)
// Status codes are: 0 - success, 1 - username taken, 2 - username/password/email empty, 3 - email taken, 4 - internal error
fn create_user(conn: &mut postgres::Client, user: UserIn) -> u8{
    if user.username.is_none() || user.password.is_none() { 
        return 2;
    }

    let username = user.username.unwrap();
    let username_status = user_by_name_exists(conn, &username);
    if username_status == 1{
        return 1;
    }else if username_status == 2 {
        return 4;
    }
    let email = user.email.unwrap();
    let email_status = user_by_email_exists(conn, &email);
    if email_status == 1 {
        return 1;
    }else if email_status == 2 {
        return 3;
    }

    let salt = random_bytes_l(32);
    let password = argon2::hash_encoded(user.password.unwrap().as_bytes(), &salt.as_bytes(), &ARGON_CONFIG).unwrap();

    let user_id = random_bytes();

    let rows_updated = conn.execute("INSERT INTO users (id, username, password, salt, email) VALUES ($1, $2, $3, $4, $5)", &[&user_id, &username, &password, &salt, &email]).unwrap();

    return if rows_updated == 1 { 0 } else { 4 };
}

fn user_by_name_exists(conn: &mut postgres::Client, input: &String) -> u8{
    let result = conn.query("SELECT username FROM users WHERE username = $1", &[input]);
    return match result {
        Ok(row) => if row.is_empty() { 0 } else { 1 },
        Err(_e) => 2
    }
}

fn user_by_email_exists(conn: &mut postgres::Client, input: &String) -> u8{
    let result = conn.query("SELECT username FROM users WHERE email = $1", &[input]);
    return match result {
        Ok(row) => if row.is_empty() { 0 } else { 1 },
        Err(_e) => 2
    }
}

fn get_access_token(conn: &mut postgres::Client, request: &AuthenticationRequest) -> AuthenticationResponse{
    let username: &String = request.username.as_ref().unwrap();
    let response_type: &String = request.response_type.as_ref().unwrap();
    let client_id: &String = request.client_id.as_ref().unwrap();
    let access_token: String = random_bytes();

    if response_type == "code"{
        let password_in: &String = request.password.as_ref().unwrap();

        let user_info = conn.query_one("SELECT password, id FROM users WHERE username=$1", &[username]);

        if user_info.is_err() {
            return AuthenticationResponse{
                access_token: None,
                refresh_token: None,
                expiration: None,
                user_id: None,
                success: false,
                status_code: Some(401),
                error: Some(String::from("401; invalid credentials")),
            };
        }

        let user_info_raw = user_info.unwrap();

        let password: String = user_info_raw.get(0);
        let user_id: String = user_info_raw.get(1);

        if argon2::verify_encoded(&password, &password_in.as_bytes()).unwrap() { 
            let start = SystemTime::now();
            let since_the_epoch = start
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");        
        
            let refresh_token: String = random_bytes();

            let seconds_since: String = (since_the_epoch.as_secs() + ACCESS_TOKEN_DURATION).to_string();
            
            let query: &String = &(String::from("DO
            $do$
            BEGIN
            IF EXISTS (SELECT FROM tokens WHERE user_id='") + &user_id + &String::from("' AND client_id='") + client_id + &String::from("') THEN
            UPDATE tokens SET access_token='") + &access_token + &String::from("', access_token_expire='") + &seconds_since + &String::from("' WHERE user_id='") +
            &user_id + &String::from("' AND client_id='") + client_id + &String::from("';
            ELSE
            INSERT INTO tokens (user_id, client_id, access_token, access_token_expire, refresh_token) VALUES ('") + &user_id + &String::from("', '") + client_id + &String::from("', '") + &access_token + &String::from("', '") + &seconds_since + &String::from("', '") + &refresh_token + &String::from("');
            END IF;
            END
            $do$"));
            
            let rows_updated = conn.execute(query.as_str(), &[]);

            if rows_updated.is_err() {
                return AuthenticationResponse{
                    access_token: None,
                    refresh_token: None,
                    user_id: None,
                    expiration: None,
                    success: false,
                    status_code: Some(500),
                    error: Some(String::from("500; internal server error")),
                };
            }

            return AuthenticationResponse{
                access_token: Some(access_token),
                refresh_token: Some(refresh_token),
                expiration: Some(since_the_epoch.as_secs() + ACCESS_TOKEN_DURATION),
                user_id: Some(user_id),
                error: None,
                status_code: Some(201),
                success: true,
            };
        }else{ 
            return AuthenticationResponse{
                access_token: None,
                refresh_token: None,
                expiration: None,
                user_id: None,
                success: false,
                status_code: Some(401),
                error: Some(String::from("401; invalid credentials")),
            };
        }
    }else if response_type == "refresh" {
        println!("Access Token refresh");
        let user_info = conn.query_one("SELECT id FROM users WHERE username=$1;", &[username]);

        if user_info.is_err() {
            return AuthenticationResponse{
                access_token: None,
                refresh_token: None,
                expiration: None,
                user_id: None,
                success: false,
                status_code: Some(401),
                error: Some(String::from("401; invalid credentials")),
            };
        }

        let user_info_raw = user_info.unwrap();

        let user_id: String = user_info_raw.get(0);


        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let mut timestamp: i64 = 0;
        timestamp = timestamp.wrapping_add((since_the_epoch.as_secs() + ACCESS_TOKEN_DURATION) as i64);

        let refresh_token: String = request.refresh_token.as_ref().unwrap().clone();
        let access_token_req = conn.execute("UPDATE tokens SET access_token = $1, access_token_expire = $5 WHERE client_id=$2 AND user_id=$3 AND refresh_token = $4;",
        &[&access_token, client_id, &user_id, &refresh_token, &timestamp]);

        if access_token_req.is_err() {
            return AuthenticationResponse{
                access_token: None,
                refresh_token: None,
                expiration: None,
                user_id: None,
                success: false,
                status_code: Some(500),
                error: Some(String::from("500; internal server error")),
            };
        }

        return AuthenticationResponse{
            access_token: Some(access_token),
            refresh_token: Some(refresh_token),
            expiration: Some(since_the_epoch.as_secs() + ACCESS_TOKEN_DURATION),
            user_id: Some(user_id),
            error: None,
            status_code: Some(201),
            success: true,
        };
    }else{
        return AuthenticationResponse{
            access_token: None,
            refresh_token: None,
            expiration: None,
            user_id: None,
            success: false,
            status_code: Some(400),
            error: Some(String::from("400; invalid response type")),
        };
    }
}

fn is_user_authentcated(conn: &mut postgres::Client, access_token: &String, client_id: &String, user_id: &String) -> (u16, String){
    let response_raw = conn.query_one("SELECT access_token_expire FROM tokens WHERE access_token=$1 AND client_id=$2 AND user_id=$3", &[access_token, client_id, user_id]);

    if response_raw.is_err() {
        return (401, String::from("{\"success\": false, \"error_code\": 401, \"error\": \"Invalid credentials\"}"));
    }

    let response = response_raw.unwrap();
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let expire_time: i64 = response.get(0);

    let mut expire_as_u: u64 = 0;
    expire_as_u = expire_as_u.wrapping_add(expire_time as u64);

    if expire_as_u < since_the_epoch.as_secs(){
        return (401, String::from("{\"success\": false, \"status_code\": 401, \"error\": \"Token expired\"}"));
    }else{
        return (200, String::from("{\"success\": true}"))
    }
}

#[post("/new", format = "json", data = "<input>", rank = 1)]
async fn new(conn: UsersDBConnection, input: Json<UserIn>) -> (Status, (ContentType, String)) {
    let status = conn.run(|c| create_user(c, input.into_inner())).await;

    return match status {
        0 => (Status::Ok, (ContentType::JSON, String::from("{\"status_code\": 201, \"error\": null, \"success\": true}"))),
        1 => (Status::Forbidden, (ContentType::JSON, String::from("{\"status_code\": 403, \"error\": \"username taken\", \"success\": false}"))),
        2 => (Status::Forbidden, (ContentType::JSON, String::from("{\"status_code\": 403, \"error\": \"username/email/password empty\", \"success\": false}"))),
        3 => (Status::Forbidden, (ContentType::JSON, String::from("{\"status_code\": 403, \"error\": \"email taken\", \"success\": false}"))),
        _ => (Status::InternalServerError, (ContentType::JSON, String::from("{\"status_code\": 500, \"error\": \"internal server error\", \"success\": false}")))
    }
}

#[post("/authenticate", format = "json", data = "<input>", rank = 1)]
async fn authenticate(conn: UsersDBConnection, input: Json<AuthenticationRequest>) -> (Status, (ContentType, String)) {
    let req = input.into_inner();
    
    if req.response_type.is_none(){
        return (Status::BadRequest, (ContentType::JSON, String::from("{\"status_code\": 400, \"error\": \"invalid request type\", \"success\": false}")));
    }

    if req.username.is_none() {
        return (Status::Unauthorized, (ContentType::JSON, String::from("{\"status_code\": 401, \"error\": \"invalid credentials\", \"success\": false}")));
    }
    
    let res = conn.run(move |c| {
        return get_access_token(c, &req);
    }).await;

    let res_json: String = rocket::serde::json::serde_json::to_string_pretty(&res).unwrap();
    return (Status::from_code(res.status_code.unwrap()).unwrap(), (ContentType::JSON, res_json));
}

#[post("/valid", format = "json", data = "<input>", rank = 1)]
async fn test_endpoint(conn: UsersDBConnection, input: Json<TestRequest>) -> (Status, (ContentType, String)){
    let res = conn.run(move |c| {
        return is_user_authentcated(c, input.access_token.as_ref().unwrap(), input.client_id.as_ref().unwrap(), input.user_id.as_ref().unwrap());
    }).await;

    return (Status::from_code(res.0).unwrap(), (ContentType::JSON, res.1));
}

#[get("/username_taken?<username>")]
async fn username_taken_endpoint(conn: UsersDBConnection, username: String) -> (Status, (ContentType, String)){
    let res = conn.run(move |c| {
        return user_by_name_exists(c, &username);
    }).await;

    if res==0 {
        return (Status::Ok, (ContentType::JSON, String::from("{\"success\": true, \"status_code\": 200, \"error\": null, \"taken\": false}")));
    }else if res==1 {
        return (Status::Ok, (ContentType::JSON, String::from("{\"success\": true, \"status_code\": 200, \"error\": null, \"taken\": true}")));
    }else {
        return (Status::InternalServerError, (ContentType::JSON, String::from("{\"success\": false, \"status_code\": 500, \"error\": \"internal server error\"}")));
    }
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("Users", |rocket| async {
        rocket.mount("/api/users", routes![new, authenticate, test_endpoint, username_taken_endpoint]).attach(UsersDBConnection::fairing())
    })
}