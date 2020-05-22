/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The tiny-auth developers
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

use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::web;

use serde_derive::Deserialize;
use serde_derive::Serialize;

use chrono::offset::Local;
use chrono::Duration;

use base64;

use log::debug;

use crate::protocol::oauth2::GrantType;
use crate::protocol::oauth2::ProtocolError;
use crate::protocol::oauth2::ClientType;
use crate::http::endpoints::render_missing_paramter_with_response;
use crate::http::state::State;

#[derive(Deserialize)]
pub struct Request {
    grant_type: Option<GrantType>,

    code: Option<String>,

    redirect_uri: Option<String>,

    client_id: Option<String>,
}

#[derive(Serialize)]
pub struct Response {
    access_token: String,

    token_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

impl Request {
    pub fn normalise(&mut self) {
        if self.code.is_some() && self.code.as_ref().unwrap().is_empty() {
            self.code = None
        }
        if self.redirect_uri.is_some() && self.redirect_uri.as_ref().unwrap().is_empty() {
            self.redirect_uri = None
        }
        if self.client_id.is_some() && self.client_id.as_ref().unwrap().is_empty() {
            self.client_id = None
        }
    }
}

pub async fn post(headers: HttpRequest, mut request: web::Form<Request>, state: web::Data<State>) -> HttpResponse {
    request.normalise();

    if request.grant_type.is_none() {
        return render_missing_paramter_with_response(ProtocolError::InvalidRequest, "Missing parameter grant_type");
    }

    if request.grant_type.as_ref().unwrap() != &GrantType::AuthorizationCode {
        return render_missing_paramter_with_response(ProtocolError::UnsupportedGrantType, "grant_type must be authorization_code");
    }

    if request.code.is_none() {
        return render_missing_paramter_with_response(ProtocolError::InvalidRequest, "Missing parameter code");
    }

    if request.redirect_uri.is_none() {
        return render_missing_paramter_with_response(ProtocolError::InvalidRequest, "Missing parameter redirect_uri");
    }

    if request.client_id.is_none() {
        return render_missing_paramter_with_response(ProtocolError::InvalidRequest, "Missing parameter client_id");
    }

    let client_id = request.client_id.as_ref().unwrap();
    let client = state.client_store.get(client_id);

    if client.is_none() {
        debug!("client '{}' not found", client_id);
        return render_missing_paramter_with_response(ProtocolError::InvalidRequest, "client id or password wrong");
    }

    let client = client.unwrap();

    if let ClientType::Confidential{..} = client.client_type {
        let (client_name, password) = match headers.headers().get("Authorization") {
            Some(value) => {
                let value = value.to_str();
                if let Err(e) = value {
                    debug!("decoding of authorization header failed. {}", e);
                    return render_missing_paramter_with_response(ProtocolError::InvalidClient, "Invalid authorization header");
                }
                let value = value.unwrap().to_string();
    
                if !value.starts_with("Basic ") {
                    debug!("Malformed HTTP basic authorization header '{}'", value);
                    return render_missing_paramter_with_response(ProtocolError::InvalidClient, "Invalid authorization header");
                }
                let value = value.replacen("Basic ", "", 1);
    
                let credentials = base64::decode(value);
                if let Err(e) = credentials {
                    debug!("base64 decoding of authorization header failed. {}", e);
                    return render_missing_paramter_with_response(ProtocolError::InvalidClient, "Invalid authorization header");
                }
                let credentials = credentials.unwrap();
    
                let credentials = String::from_utf8(credentials);
                if let Err(e) = credentials {
                    debug!("utf-8 decoding of authorization header failed. {}", e);
                    return render_missing_paramter_with_response(ProtocolError::InvalidClient, "Invalid authorization header");
                }
                let credentials = credentials.unwrap();
    
                let split: Vec<String> = credentials.splitn(2, ':').map(str::to_string).collect();
                if split.len() == 2 {
                    (split[0].clone(), split[1].clone())
                } else {
                    return render_missing_paramter_with_response(ProtocolError::InvalidClient, "Invalid authorization header");
                }
            }
            None => return render_missing_paramter_with_response(ProtocolError::InvalidClient, "Missing authorization header")
        };
    
        if *client_id != client_name {
            return render_missing_paramter_with_response(ProtocolError::InvalidClient, "Invalid authorization header");
        }
    
        if !client.is_password_correct(&password) {
            return render_missing_paramter_with_response(ProtocolError::InvalidClient, "client id or password wrong");
        }
    }

    let code = request.code.as_ref().unwrap();
    let stored_redirect_uri = state.auth_code_store.validate(client_id, &code, Local::now());
    if stored_redirect_uri.is_none() {
        debug!("No authorization code found for client '{}' with code '{}'", client_id, code);
        return render_missing_paramter_with_response(ProtocolError::InvalidGrant, "Invalid code");
    }
    let stored_redirect_uri = stored_redirect_uri.unwrap();

    if &stored_redirect_uri.0 != request.redirect_uri.as_ref().unwrap() {
        debug!("redirect_uri is wrong");
        return render_missing_paramter_with_response(ProtocolError::InvalidGrant, "Invalid code");
    }

    if stored_redirect_uri.1 < Duration::zero() {
        debug!("code has expired");
        return render_missing_paramter_with_response(ProtocolError::InvalidGrant, "Invalid code");
    }

    HttpResponse::Ok()
        .json(Response {
            access_token: "dummy_token".to_string(),
            token_type: "bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::test;
    use actix_web::http;
    use actix_web::web::Data;
    use actix_web::web::Form;

    use crate::http::endpoints::ErrorResponse;
    use crate::http::endpoints::tests::read_response;
    use crate::http::state::tests::build_test_state;
    use crate::protocol::oauth2::ProtocolError;

    #[actix_rt::test]
    async fn missing_grant_type_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: None,
            code: Some("fdsa".to_string()),
            client_id: Some("fdsa".to_string()),
            redirect_uri: Some("fdsa".to_string()),
        });
        let state = Data::new(build_test_state());
        let resp = post(req, form, state).await;
        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(ProtocolError::InvalidRequest, response.error);
    }
}