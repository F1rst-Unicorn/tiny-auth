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

use crate::endpoints::return_rendered_template;
use crate::{ApiUrl, WebBasePath};
use actix_web::http::header::LOCATION;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
use tiny_auth_business::issuer_configuration::IssuerConfiguration;
use tiny_auth_business::template::web::{ErrorPage, WebTemplater, WebappRootContext};
use tracing::{instrument, trace};

#[instrument(skip_all, name = "webapp_redirect")]
pub async fn redirect(request: HttpRequest, web_base_path: Data<WebBasePath>) -> HttpResponse {
    let location = if request.query_string() != "" {
        web_base_path.0.to_owned() + "/?" + request.query_string()
    } else {
        web_base_path.0.to_owned() + "/"
    };
    trace!(%location, "redirecting");
    HttpResponse::TemporaryRedirect()
        .append_header((LOCATION, location))
        .finish()
}

#[instrument(skip_all, name = "webapp")]
pub async fn get(
    templater: Data<dyn for<'a> WebTemplater<WebappRootContext<'a>>>,
    issuer_config: Data<IssuerConfiguration>,
    api_url: Data<ApiUrl>,
    web_base_path: Data<WebBasePath>,
) -> HttpResponse {
    trace!("rendering webapp");
    let context = WebappRootContext {
        provider_url: issuer_config.issuer_url.as_str(),
        api_url: api_url.0.as_str(),
        web_base: web_base_path.0.as_str(),
    };
    return_rendered_template(templater.instantiate(context), StatusCode::OK, || {
        templater.instantiate_error_page(ErrorPage::ServerError)
    })
}
