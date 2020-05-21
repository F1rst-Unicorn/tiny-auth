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

use actix_web::HttpResponse;
use actix_web::web;

use actix_session::Session;

use tera::Context;
use tera::Tera;

use log::debug;
use log::error;

use crate::http::state::State;
use crate::http::endpoints::server_error;
use crate::http::endpoints::authorize;

use serde_derive::Serialize;
use serde_derive::Deserialize;

pub const SESSION_KEY: &str = "b";
const ERROR_CODE_SESSION_KEY: &str = "e";

#[derive(Serialize, Deserialize)]
pub struct Request {
    #[serde(skip_serializing_if = "Option::is_none")] 
    username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")] 
    password: Option<String>,
}

impl Request {
    fn normalise(&mut self) {
        if self.username.is_some() && self.username.as_ref().unwrap().is_empty() {
            debug!("normalising empty username to None");
            self.username = None
        }
        if self.password.is_some() && self.password.as_ref().unwrap().is_empty() {
            debug!("normalising empty password to None");
            self.password = None
        }
    }
}

pub async fn get(state: web::Data<State>, session: Session) -> HttpResponse {
    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!("Unsolicited authentication request. {:?}", first_request);
        return render_invalid_authentication_request(&state.tera);
    }

    let mut context = Context::new();
    if let Some(error_code) = session.get::<u64>(ERROR_CODE_SESSION_KEY).expect("failed to deserialize") {
        context.insert("error", &error_code);
    }
    let body = state.tera.render("authenticate.html.j2", &context);
    match body {
        Ok(body) => {
            session.renew();
            HttpResponse::Ok().body(body)
        }
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn post(mut query: web::Form<Request>, state: web::Data<State>, session: Session) -> HttpResponse {
    query.normalise();

    session.remove(ERROR_CODE_SESSION_KEY);
    
    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!("Unsolicited authentication request. {:?}", first_request);
        return render_invalid_authentication_request(&state.tera);
    }

    if query.username.is_none() {
        debug!("missing username");
        if let Err(e) = session.set(ERROR_CODE_SESSION_KEY, 1) {
            error!("Failed to serialise session: {}", e);
            return server_error(&state.tera);
        }
        return HttpResponse::SeeOther()
            .set_header("Location", "authenticate")
            .finish()
    }

    if query.password.is_none() {
        debug!("missing password");
        if let Err(e) = session.set(ERROR_CODE_SESSION_KEY, 2) {
            error!("Failed to serialise session: {}", e);
            return server_error(&state.tera);
        }
        return HttpResponse::SeeOther()
            .set_header("Location", "authenticate")
            .finish()
    }

    let username = query.username.clone().expect("checked before");
    let user = state.user_store.get(&username);

    if user.is_none() {
        debug!("user '{}' not found", username);
        if let Err(e) = session.set(ERROR_CODE_SESSION_KEY, 3) {
            error!("Failed to serialise session: {}", e);
            return server_error(&state.tera);
        }
        return HttpResponse::SeeOther()
            .set_header("Location", "authenticate")
            .finish()
    }

    let user = user.expect("checked before");
    let password = query.password.clone().expect("checked before");

    if user.is_password_correct(&password) {
        if let Err(e) = session.set("b", 1) {
            error!("Failed to serialise session: {}", e);
            return server_error(&state.tera);
        }
        HttpResponse::SeeOther()
            .set_header("Location", "consent")
            .finish()
    } else {
        debug!("password of user '{}' wrong", username);
        if let Err(e) = session.set(ERROR_CODE_SESSION_KEY, 3) {
            error!("Failed to serialise session: {}", e);
            return server_error(&state.tera);
        }
        HttpResponse::SeeOther()
            .set_header("Location", "authenticate")
            .finish()
    }
}

pub fn render_invalid_authentication_request(tera: &Tera) -> HttpResponse {
    let body = tera.render("invalid_authentication_request.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::BadRequest().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}