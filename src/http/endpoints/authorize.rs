/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The cinit developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use crate::protocol::oauth2::ResponseType;
use crate::protocol::oauth2::ProtocolError;
use crate::http::state;

use actix_web::HttpResponse;
use actix_web::web;

use serde_derive::Deserialize;
 
use tera::Tera;
use tera::Context;

use url::Url;

use log::trace;

#[derive(Deserialize)]
pub struct Request {
    scope: Option<String>,

    response_type: Option<ResponseType>,

    client_id: Option<String>,

    redirect_uri: Option<String>,

    state: Option<String>,

    response_mode: Option<String>,

    nonce: Option<String>,

    display: Option<String>,

    prompt: Option<String>,

    max_age: Option<String>,

    ui_locales: Option<String>,

    id_token_hint: Option<String>,

    login_hint: Option<String>,

    acr_values: Option<String>,
}

impl Request {
    fn normalise(&mut self) {
        if self.scope.is_some() && self.scope.as_ref().unwrap().is_empty() {
            self.scope = None
        }
        if self.client_id.is_some() && self.client_id.as_ref().unwrap().is_empty() {
            self.client_id = None
        }
        if self.redirect_uri.is_some() && self.redirect_uri.as_ref().unwrap().is_empty() {
            self.redirect_uri = None
        }
        if self.state.is_some() && self.state.as_ref().unwrap().is_empty() {
            self.state = None
        }
        if self.response_mode.is_some() && self.response_mode.as_ref().unwrap().is_empty() {
            self.response_mode = None
        }
        if self.nonce.is_some() && self.nonce.as_ref().unwrap().is_empty() {
            self.nonce = None
        }
        if self.display.is_some() && self.display.as_ref().unwrap().is_empty() {
            self.display = None
        }
        if self.prompt.is_some() && self.prompt.as_ref().unwrap().is_empty() {
            self.prompt = None
        }
        if self.max_age.is_some() && self.max_age.as_ref().unwrap().is_empty() {
            self.max_age = None
        }
        if self.ui_locales.is_some() && self.ui_locales.as_ref().unwrap().is_empty() {
            self.ui_locales = None
        }
        if self.id_token_hint.is_some() && self.id_token_hint.as_ref().unwrap().is_empty() {
            self.id_token_hint = None
        }
        if self.login_hint.is_some() && self.login_hint.as_ref().unwrap().is_empty() {
            self.login_hint = None
        }
        if self.acr_values.is_some() && self.acr_values.as_ref().unwrap().is_empty() {
            self.acr_values = None
        }
    }
}

pub async fn get(query: web::Query<Request>, state: web::Data<state::State>) -> HttpResponse {
    post(query, state).await
}

pub async fn post(mut query: web::Query<Request>, state: web::Data<state::State>) -> HttpResponse {
    trace!("authorize");
    query.normalise();
    
    if query.client_id.is_none() {
        return render_invalid_client_id_error(&state.tera);
    }

    if query.redirect_uri.is_none() {
        return render_invalid_redirect_uri_error(&state.tera);
    }

    let redirect_uri = query.redirect_uri.as_ref().unwrap();
    let client_id = query.client_id.as_ref().unwrap();

    let client = state.client_store.get(client_id);

    if client.is_none() {
        return render_invalid_client_id_error(&state.tera);
    }
    
    let client = client.expect("checked before");

    if ! client.is_redirect_uri_valid(&redirect_uri) {
        return render_invalid_redirect_uri_error(&state.tera);
    }

    if query.scope.is_none() {
        return missing_parameter(&redirect_uri, "scope", &query.state);
    }

    if query.response_type.is_none() {
        return missing_parameter(&redirect_uri, "response_type", &query.state);
    }

    HttpResponse::Ok().finish()
}

pub fn missing_parameter(redirect_uri: &str, name: &str, state: &Option<String>) -> HttpResponse {
    let mut url = Url::parse(redirect_uri).expect("should have been validated upon registration");
    url.query_pairs_mut()
        .append_pair("error", &serde_urlencoded::to_string(ProtocolError::InvalidRequest).unwrap())
        .append_pair("error_description", &serde_urlencoded::to_string(format!("Missing required parameter {}", name)).unwrap());

    if let Some(state) = state {
        url.query_pairs_mut()
            .append_pair("state", state);
    }

    HttpResponse::TemporaryRedirect()
        .set_header("Location", url.as_str())
        .finish()
}

pub fn render_invalid_client_id_error(tera: &Tera) -> HttpResponse {
    let body = tera.render("invalid_client_id.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::BadRequest().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub fn render_invalid_redirect_uri_error(tera: &Tera) -> HttpResponse {
    let body = tera.render("invalid_redirect_uri.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::BadRequest().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}