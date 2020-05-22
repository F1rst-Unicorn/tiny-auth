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

use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use url::Url;

use chrono::offset::Local;

use tera::Context;

use log::debug;
use log::error;

use crate::http::endpoints::authenticate;
use crate::http::endpoints::authorize;
use crate::http::endpoints::server_error;
use crate::http::state::State;

pub async fn get(state: web::Data<State>, session: Session) -> HttpResponse {
    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!("Unsolicited consent request. {:?}", first_request);
        return render_invalid_consent_request(&state.tera);
    }

    let authenticated = session.get::<i32>(authenticate::SESSION_KEY);
    if authenticated.is_err() || authenticated.as_ref().unwrap().is_none() {
        debug!("Unsolicited consent request. {:?}", authenticated);
        return render_invalid_consent_request(&state.tera);
    }

    let body = state.tera.render("consent.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn post(session: Session, state: web::Data<State>) -> HttpResponse {
    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!("Unsolicited consent request. {:?}", first_request);
        return render_invalid_consent_request(&state.tera);
    }

    let authenticated = session.get::<i32>(authenticate::SESSION_KEY);
    if authenticated.is_err() || authenticated.as_ref().unwrap().is_none() {
        debug!("Unsolicited consent request. {:?}", authenticated);
        return render_invalid_consent_request(&state.tera);
    }

    let first_request_result =
        serde_urlencoded::from_str::<authorize::Request>(&first_request.unwrap().unwrap());

    if let Err(e) = first_request_result {
        error!("Failed to deserialize initial request. {}", e);
        return server_error(&state.tera);
    }

    let first_request = first_request_result.unwrap();
    let redirect_uri = first_request.redirect_uri.unwrap();
    let mut url = Url::parse(&redirect_uri).expect("should have been validated upon registration");

    let code = state.auth_code_store.get_authorization_code(
        first_request.client_id.as_ref().unwrap(),
        &redirect_uri,
        Local::now(),
    );

    url.query_pairs_mut().append_pair("code", &code);

    if let Some(state) = first_request.state {
        url.query_pairs_mut().append_pair("state", &state);
    }

    HttpResponse::SeeOther()
        .set_header("Location", url.as_str())
        .finish()
}

pub fn render_invalid_consent_request(tera: &tera::Tera) -> HttpResponse {
    let body = tera.render("invalid_consent_request.html.j2", &tera::Context::new());
    match body {
        Ok(body) => HttpResponse::BadRequest()
            .set_header("Content-Type", "text/html")
            .body(body),
        Err(e) => {
            log::warn!("{}", e);
            server_error(tera)
        }
    }
}
