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

use std::sync::Arc;

use u2f::messages::*;
use u2f::protocol::*;
use u2f::register::*;

use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use tera::Context;
use tera::Tera;

use log::debug;
use log::error;

use crate::http::endpoints::authenticate::render_invalid_authentication_request;
use crate::http::endpoints::parse_first_request;
use crate::store::UserStore;

pub const SESSION_KEY: &str = "u";
pub const SIGN_SESSION_KEY: &str = "s";

pub async fn get(tera: web::Data<Tera>) -> HttpResponse {
    let body = tera.render("u2f.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::Ok()
            .set_header("Content-Type", "text/html")
            .body(body),
        Err(e) => {
            log::warn!("{}", super::render_tera_error(&e));
            super::server_error(&tera)
        }
    }
}

pub async fn get_u2f(session: Session, tera: web::Data<Tera>) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(&tera);
        }
        Some(v) => v,
    };

    let username = match session.get::<String>(super::authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited u2f authentication request, missing authentication session key");
            return render_invalid_authentication_request(&tera);
        }
        Ok(Some(v)) => v,
    };

    let body = tera.render("u2f_authenticate.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::Ok()
            .set_header("Content-Type", "text/html")
            .body(body),
        Err(e) => {
            log::warn!("{}", super::render_tera_error(&e));
            super::server_error(&tera)
        }
    }
}

pub async fn register_request(
    session: Session,
    state: web::Data<U2f>,
    tera: web::Data<Tera>,
) -> HttpResponse {
    let challenge = match state.generate_challenge() {
        Err(e) => {
            error!("Failed to generate challenge: {}", e);
            return super::server_error(&tera);
        }
        Ok(v) => v,
    };

    let challenge_str = match serde_json::to_string(&challenge) {
        Err(e) => {
            error!("Failed to serialize challenge: {}", e);
            return super::server_error(&tera);
        }
        Ok(v) => v,
    };

    if let Err(e) = session.set(SESSION_KEY, challenge_str) {
        error!("Failed to store challenge string: {}", e);
        return super::server_error(&tera);
    }

    let u2f_request = match state.request(challenge, vec![]) {
        Err(e) => {
            error!("Failed to build challenge request: {}", e);
            return super::server_error(&tera);
        }
        Ok(v) => v,
    };

    HttpResponse::Ok().json(u2f_request)
}

pub async fn register_response(
    session: Session,
    response: web::Json<RegisterResponse>,
    state: web::Data<U2f>,
    tera: web::Data<Tera>,
) -> HttpResponse {
    let challenge = match session.get::<String>(SESSION_KEY) {
        Err(e) => {
            error!("Failed to get challenge from cookie: {}", e);
            return super::server_error(&tera);
        }
        Ok(None) => {
            error!("No challenge given");
            return super::server_error(&tera);
        }
        Ok(Some(v)) => v,
    };
    session.remove(SESSION_KEY);

    let challenge: Challenge = match serde_json::from_str(&challenge) {
        Err(e) => {
            error!("Failed to deserialize challenge from cookie: {}", e);
            return super::server_error(&tera);
        }
        Ok(v) => v,
    };

    match state.register_response(challenge, response.into_inner()) {
        Ok(registration) => HttpResponse::Ok().json(registration),
        Err(e) => {
            error!("Registration failed: {}", e);
            return super::server_error(&tera);
        }
    }
}

pub async fn sign_request(
    session: Session,
    state: web::Data<U2f>,
    user_store: web::Data<Arc<dyn UserStore>>,
    tera: web::Data<Tera>,
) -> HttpResponse {
    let challenge = match state.generate_challenge() {
        Err(e) => {
            error!("Failed to generate challenge: {}", e);
            return super::server_error(&tera);
        }
        Ok(v) => v,
    };

    let challenge_str = match serde_json::to_string(&challenge) {
        Err(e) => {
            error!("Failed to serialize challenge: {}", e);
            return super::server_error(&tera);
        }
        Ok(v) => v,
    };

    if let Err(e) = session.set(SESSION_KEY, challenge_str) {
        error!("Failed to set challenge to cookie: {}", e);
        return super::server_error(&tera);
    }

    let username = match session.get::<String>(super::authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            error!("No username found in session");
            return super::authenticate::render_invalid_authentication_request(&tera);
        }
        Ok(Some(v)) => v,
    };

    let user = match user_store.get(&username) {
        None => {
            error!("user '{}' not found", username);
            return super::authenticate::render_invalid_authentication_request(&tera);
        }
        Some(v) => v,
    };

    let signed_request = state.sign_request(challenge, user.get_u2f_registrations());

    HttpResponse::Ok().json(signed_request)
}

pub async fn sign_response(
    session: Session,
    response: web::Json<SignResponse>,
    user_store: web::Data<Arc<dyn UserStore>>,
    tera: web::Data<Tera>,
    state: web::Data<U2f>,
) -> HttpResponse {
    let challenge = match session.get::<String>(SESSION_KEY) {
        Err(e) => {
            error!("Failed to get challenge from cookie: {}", e);
            return super::server_error(&tera);
        }
        Ok(None) => {
            error!("No challenge given");
            return super::server_error(&tera);
        }
        Ok(Some(v)) => v,
    };
    session.remove(SESSION_KEY);

    let challenge: Challenge = match serde_json::from_str(&challenge) {
        Err(e) => {
            error!("Failed to deserialize challenge from cookie: {}", e);
            return super::server_error(&tera);
        }
        Ok(v) => v,
    };

    let username = match session.get::<String>(super::authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            error!("No username found in session");
            return super::authenticate::render_invalid_authentication_request(&tera);
        }
        Ok(Some(v)) => v,
    };

    let user = match user_store.get(&username) {
        None => {
            error!("user '{}' not found", username);
            return super::authenticate::render_invalid_authentication_request(&tera);
        }
        Some(v) => v,
    };

    let mut _counter: u32 = 0;
    for registration in user.get_u2f_registrations() {
        let response =
            state.sign_response(challenge.clone(), registration, response.clone(), _counter);
        match response {
            Ok(new_counter) => {
                _counter = new_counter;
                return HttpResponse::SeeOther()
                    .set_header("Location", "consent")
                    .finish();
            }
            Err(_e) => {
                break;
            }
        }
    }

    HttpResponse::Unauthorized().finish()
}
