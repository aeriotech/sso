use std::collections::HashMap;
use rocket_dyn_templates::{Template};
use rocket::serde::json::serde_json::json;
use super::super::api::clients::{get_client_info, ClientInfo, scope_to_vec};
use super::super::db::UsersDBConnection;

#[get("/?<client_id>&<scope>&<redirect_uri>", rank = 1)]
async fn login(conn: UsersDBConnection, client_id: String, scope: u64, redirect_uri: String) -> Template{
    let client_info: ClientInfo = conn.run(move |c| {
        return get_client_info(c, &client_id);
    }).await;

    if client_info.success {
        let scope_json = scope_to_vec(scope);
        if scope_json.is_none() {
            let mut context: HashMap<&str, &str> = HashMap::new();
            context.insert("error", "Invalid scope");
            return Template::render("error", context);
        }

        let client_name: String = client_info.client_name.unwrap();
        let client_id_: String = client_info.client_id.unwrap();

        let json_data = json!({
            "client_id": client_id_,
            "scope": scope_json.unwrap(),
            "scope_num": scope,
            "redirect_uri": redirect_uri,
            "client_name": client_name
        });

        return Template::render("login", json_data);
    } else {
        let mut context: HashMap<&str, &str> = HashMap::new();
        context.insert("error", "Invalid client id");
        return Template::render("error", context);
    }
}

#[get("/?<client_id>&<scope>&<redirect_uri>", rank = 2)]
async fn login_invalid_scope(client_id: String, scope: String, redirect_uri: String) -> Template{
    let mut context: HashMap<&str, &str> = HashMap::new();
    context.insert("error", "Invalid scope");
    return Template::render("error", context);
}

pub fn stage() -> Vec<rocket::Route> {
    routes![login, login_invalid_scope]
}