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

pub mod authenticate;
pub mod token;
pub mod authorize;
pub mod userinfo;
pub mod consent;

use crate::protocol::oauth2::ProtocolError;

use actix_web::HttpResponse;

use url::Url;

pub fn missing_parameter(redirect_uri: &str, error: ProtocolError, description: &str, state: &Option<String>) -> HttpResponse {
    let mut url = Url::parse(redirect_uri).expect("should have been validated upon registration");

    url.query_pairs_mut()
        .append_pair("error", &format!("{}", error))
        .append_pair("error_description", description);

    if let Some(state) = state {
        url.query_pairs_mut()
            .append_pair("state", state);
    }

    HttpResponse::TemporaryRedirect()
        .set_header("Location", url.as_str())
        .finish()
}

pub fn server_error(tera: &tera::Tera) -> HttpResponse {
    let body = tera.render("500.html.j2", &tera::Context::new());
    match body {
        Ok(body) => HttpResponse::InternalServerError().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    } 
}