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

use u2f::messages::*;
use u2f::protocol::*;
use u2f::register::*;

use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use tera::Context;
use tera::Tera;

use log::error;

pub const SESSION_KEY: &str = "u";

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

pub async fn register_request(session: Session, state: web::Data<U2f>) -> HttpResponse {
    let challenge = match state.generate_challenge() {
        Err(e) => {
            error!("Failed to generate challenge: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
        Ok(v) => v,
    };

    let challenge_str = match serde_json::to_string(&challenge) {
        Err(e) => {
            error!("Failed to serialize challenge: {}", e);
            return HttpResponse::InternalServerError().body("");
        }
        Ok(v) => v,
    };

    if let Err(e) = session.set(SESSION_KEY, challenge_str) {
        error!("Failed to store challenge string: {}", e);
        return HttpResponse::InternalServerError().finish();
    }

    let u2f_request = match state.request(challenge, vec![]) {
        Err(e) => {
            error!("Failed to build challenge request: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
        Ok(v) => v,
    };

    HttpResponse::Ok().json(u2f_request)
}

pub async fn register_response(
    session: Session,
    response: web::Json<RegisterResponse>,
    state: web::Data<U2f>,
) -> HttpResponse {
    let challenge = match session.get::<String>(SESSION_KEY) {
        Err(e) => {
            error!("Failed to get challenge from cookie: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
        Ok(None) => {
            error!("No challenge given");
            return HttpResponse::BadRequest().finish();
        }
        Ok(Some(v)) => v,
    };
    session.remove(SESSION_KEY);

    let challenge: Challenge = match serde_json::from_str(&challenge) {
        Err(e) => {
            error!("Failed to deserialize challenge from cookie: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
        Ok(v) => v,
    };

    match state.register_response(challenge, response.into_inner()) {
        Ok(registration) => HttpResponse::Ok().json(registration),
        Err(e) => {
            error!("Registration failed: {}", e);
            HttpResponse::BadRequest().finish()
        }
    }
}
/*
pub async fn sign_request(mut cookies: Cookies, state: State<U2fClient>) -> HttpResponse {
    let challenge = state.u2f.generate_challenge().unwrap();
    let challenge_str = serde_json::to_string(&challenge);

    // Only for this demo we will keep the challenge in a private (encrypted) cookie
    cookies.add_private(Cookie::new("challenge", challenge_str.unwrap()));

    let signed_request = state.u2f.sign_request(challenge, REGISTRATIONS.lock().unwrap().clone());

    return Json(signed_request);
}

pub async fn sign_response(mut cookies: Cookies, response: Json<SignResponse>, state: State<U2fClient>) -> HttpResponse {
    let cookie = cookies.get_private("challenge");
    if let Some(ref cookie) = cookie {
        let challenge: Challenge = serde_json::from_str(cookie.value()).unwrap();

        let registrations = REGISTRATIONS.lock().unwrap().clone();
        let sign_resp = response.into_inner();

        let mut _counter: u32 = 0;
        for registration in registrations {
            let response = state.u2f.sign_response(challenge.clone(), registration, sign_resp.clone(), _counter);
            match response {
                Ok(new_counter) =>  {
                    _counter = new_counter;
                    return Ok(json!({"status": "success"}));
                },
                Err(_e) => {
                    break;
                }
            }
        }
        return Err(NotFound(format!("error verifying response")));
    } else {
        return Err(NotFound(format!("Not able to recover challenge")));
    }
}*/
