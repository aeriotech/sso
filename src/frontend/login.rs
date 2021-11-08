use std::collections::HashMap;
use rocket_dyn_templates::{Template};
use rocket::serde::json::serde_json::json;
use crate::api::clients::{get_client_info, ClientInfo, scope_to_vec};
use crate::api::users::{get_username_by_id, is_user_session_authenticated};
use crate::db::UsersDBConnection;
use rocket::http::{CookieJar, Cookie};
use rocket_dyn_templates::handlebars::JsonValue;

#[get("/?<client_id>&<scope>&<redirect_uri>&<forget>", rank = 1)]
async fn login(conn: UsersDBConnection, cookies: &CookieJar<'_>, client_id: String, scope: u64, redirect_uri: String, forget: Option<bool>) -> Template{
    let client_info: ClientInfo = conn.run(move |c| {
        return get_client_info(c, &client_id);
    }).await;

    let forget_user: bool = forget.unwrap_or(false);

    if client_info.success {
        let scope_vec = scope_to_vec(scope);
        if scope_vec.is_none() {
            let mut context: HashMap<&str, &str> = HashMap::new();
            context.insert("error", "Invalid scope");
            return Template::render("error", context);
        }
        let client_name: String = client_info.client_name.unwrap();
        let client_id_: String = client_info.client_id.unwrap();
        let scopes: Vec<String> = scope_vec.unwrap();

        let mut json_data = json!({
            "client_id": client_id_,
            "scope": scopes,
            "scope_num": scope,
            "redirect_uri": redirect_uri,
            "client_name": client_name
        });

        if !forget_user {
            let user_id_cookie = cookies.get_private("user_id");
            let series_id_cookie = cookies.get_private("series_id");
            let token_cookie = cookies.get_private("token");
            
            if series_id_cookie.is_some() && token_cookie.is_some() && user_id_cookie.is_some() {
                let series_id: String = String::from(series_id_cookie.unwrap().value());
                let token: String = String::from(token_cookie.unwrap().value());
                // TODO: find a better way to do this
                let user_id: String = String::from(user_id_cookie.unwrap().value());
                let user_id__: String = user_id.clone();
                
                let res = conn.run(move |c| {
                    return is_user_session_authenticated(c, user_id, series_id, token);
                }).await;

                if res == 0 {
                    let username: String = conn.run(move |c| {
                        return get_username_by_id(c, &user_id__);
                    }).await;

                    if !username.is_empty() && username!="err" {
                        json_data["username"] = JsonValue::String(username);
                        return Template::render("logged_in", json_data);
                    }
                }
            }
        }else {
            cookies.remove_private(Cookie::named("user_id"));
            cookies.remove_private(Cookie::named("series_id"));
            cookies.remove_private(Cookie::named("token"));
        }

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