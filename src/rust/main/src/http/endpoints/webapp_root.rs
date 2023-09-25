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

use crate::http::endpoints::render_template_with_context;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::HttpResponse;
use tera::Context;
use tera::Tera;
use tiny_auth_business::issuer_configuration::IssuerConfiguration;

pub async fn get(tera: Data<Tera>, issuer_config: Data<IssuerConfiguration>) -> HttpResponse {
    let mut context = Context::new();
    context.insert("tiny_auth_provider_url", &issuer_config.issuer_url);
    render_template_with_context("index.html.j2", StatusCode::OK, &tera, &context)
}
