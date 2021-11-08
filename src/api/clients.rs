use rocket::http::{Status, ContentType};
use rocket_sync_db_pools::postgres;
use rocket::serde::{Serialize, Deserialize};
use crate::db::UsersDBConnection;

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ClientInfo{
    pub client_name: Option<String>,
    pub client_id: Option<String>,
    pub internal: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub success: bool
}

// Possible scopes: 0 - all, 1 - email, 2 - username
pub fn scope_to_vec(scope: u64) -> Option<Vec<String>> {
    let mut json: Vec<String> = Vec::new();

    if scope == 0 {
        json.insert(0, String::from("Email"));
        json.insert(1, String::from("Username"));
        return Some(json);
    }
    if scope & 1 == 1 {
        json.insert(0, String::from("Email"));
    }
    if scope & 2 == 2 {
        json.insert(0, String::from("Username"));
    }

    if json.is_empty(){
        return None;
    }

    return Some(json);
}

pub fn get_client_info(conn: &mut postgres::Client, client_id: &String) -> ClientInfo {
    let client_info = conn.query_one("SELECT client_name, internal FROM clients WHERE client_id=$1", &[client_id]);

    if client_info.is_err() {
        return ClientInfo{
            client_name: None,
            client_id: None,
            internal: false,
            status_code: Some(401),
            error: Some(String::from("401; invalid client id")),
            success: false
        };
    }

    let client_info_raw = client_info.unwrap();

    let client_name: String = client_info_raw.get(0);
    let internal: bool = client_info_raw.get(1);

    return ClientInfo{
        client_name: Some(client_name),
        internal,
        client_id: Some(client_id.clone()),
        status_code: Some(200),
        error: None,
        success: true
    };
}

#[get("/<client_id>")]
async fn get(conn: UsersDBConnection, client_id: String) -> (Status, (ContentType, String)) {
    let res: ClientInfo = conn.run(move |c| {
        return get_client_info(c, &client_id);
    }).await;

    let res_json: String = rocket::serde::json::serde_json::to_string_pretty(&res).unwrap();
    return (Status::from_code(res.status_code.unwrap()).unwrap(), (ContentType::JSON, res_json));
}

pub fn stage() -> Vec<rocket::Route> {
    routes![get]
}