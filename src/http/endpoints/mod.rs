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
pub mod authorize;
pub mod consent;
pub mod token;
pub mod userinfo;

use crate::protocol::oauth2::ProtocolError;

use actix_web::HttpResponse;

use url::Url;

use serde_derive::Deserialize;
use serde_derive::Serialize;

pub fn missing_parameter(
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
) -> HttpResponse {
    let mut url = Url::parse(redirect_uri).expect("should have been validated upon registration");

    url.query_pairs_mut()
        .append_pair("error", &format!("{}", error))
        .append_pair("error_description", description);

    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }

    HttpResponse::TemporaryRedirect()
        .set_header("Location", url.as_str())
        .finish()
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: ProtocolError,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
}

pub fn render_missing_paramter_with_response(
    error: ProtocolError,
    description: &str,
) -> HttpResponse {
    match error {
        ProtocolError::InvalidClient => HttpResponse::Unauthorized(),
        _ => HttpResponse::BadRequest(),
    }
    .json(ErrorResponse {
        error,
        error_description: Some(description.to_string()),
        error_uri: None,
    })
}

pub fn server_error(tera: &tera::Tera) -> HttpResponse {
    let body = tera.render("500.html.j2", &tera::Context::new());
    match body {
        Ok(body) => HttpResponse::InternalServerError()
            .set_header("Content-Type", "text/html")
            .body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[cfg(test)]
mod tests {

    use actix_web::web::BytesMut;
    use actix_web::HttpResponse;
    use futures::stream::StreamExt;
    use serde::de::DeserializeOwned;

    pub async fn read_response<T: DeserializeOwned>(mut resp: HttpResponse) -> T {
        let mut body = resp.take_body();
        let mut bytes = BytesMut::new();
        while let Some(item) = body.next().await {
            bytes.extend_from_slice(&item.unwrap());
        }
        serde_json::from_slice::<T>(&bytes).expect("Failed to deserialize response")
    }
}
