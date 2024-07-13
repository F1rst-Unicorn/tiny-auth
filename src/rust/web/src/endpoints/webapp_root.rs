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

use crate::endpoints::render_template_with_context;
use crate::{ApiUrl, WebBasePath};
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
use tera::Context;
use tera::Tera;
use tiny_auth_business::issuer_configuration::IssuerConfiguration;
use tracing::instrument;

#[instrument(skip_all, fields(transport = "http"))]
pub async fn redirect(request: HttpRequest, web_base_path: Data<WebBasePath>) -> HttpResponse {
    let location = if request.query_string() != "" {
        web_base_path.0.to_string() + "/?" + request.query_string()
    } else {
        web_base_path.0.to_string() + "/"
    };
    HttpResponse::TemporaryRedirect()
        .append_header(("Location", location))
        .finish()
}

#[instrument(skip_all, fields(transport = "http"))]
pub async fn get(
    tera: Data<Tera>,
    issuer_config: Data<IssuerConfiguration>,
    api_url: Data<ApiUrl>,
    web_base_path: Data<WebBasePath>,
) -> HttpResponse {
    let mut context = Context::new();
    context.insert("tiny_auth_provider_url", &issuer_config.issuer_url);
    context.insert("tiny_auth_api_url", &api_url.0);
    context.insert("tiny_auth_web_base", &web_base_path.0);
    render_template_with_context("index.html.j2", StatusCode::OK, &tera, &context)
}
