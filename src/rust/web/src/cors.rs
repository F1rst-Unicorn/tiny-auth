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

use actix_web::http::header::HeaderValue;
use actix_web::http::header::ACCESS_CONTROL_ALLOW_METHODS;
use actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN;
use actix_web::http::header::ACCESS_CONTROL_MAX_AGE;
use actix_web::http::header::ORIGIN;
use actix_web::web;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::HttpResponseBuilder;
use std::sync::Arc;
use tiny_auth_business::cors::CorsLister;

use tracing::{debug, instrument};

#[instrument(skip_all, fields(transport = "http"))]
pub async fn cors_options_preflight(
    request: HttpRequest,
    cors_lister: web::Data<Arc<dyn CorsLister>>,
) -> HttpResponse {
    match CorsChecker::new(cors_lister.get_ref().clone()).check(&request) {
        CorsCheckResult::NoOrigin => {
            debug!("rejecting CORS OPTIONS request without origin");
            render_invalid_request()
        }
        CorsCheckResult::IllegalOrigin => render_invalid_request(),
        approved @ CorsCheckResult::ApprovedOrigin(_) => {
            approved.with_headers(HttpResponse::NoContent()).finish()
        }
    }
}

pub fn render_invalid_request() -> HttpResponse {
    HttpResponse::BadRequest().finish()
}

#[derive(Clone)]
pub struct CorsChecker {
    lister: Arc<dyn CorsLister>,
}

impl CorsChecker {
    pub fn new(lister: Arc<dyn CorsLister>) -> Self {
        Self { lister }
    }

    pub fn check<'a>(&self, request: &'a HttpRequest) -> CorsCheckResult<'a> {
        match request
            .headers()
            .get(ORIGIN)
            .map(HeaderValue::to_str)
            .and_then(Result::ok)
        {
            None => CorsCheckResult::NoOrigin,
            Some(origin) => {
                if self.lister.is_cors_allowed(origin) {
                    CorsCheckResult::ApprovedOrigin(origin)
                } else {
                    debug!("CORS check for unapproved domain '{}'", origin);
                    CorsCheckResult::IllegalOrigin
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub enum CorsCheckResult<'a> {
    NoOrigin,
    IllegalOrigin,
    ApprovedOrigin(&'a str),
}

impl<'a> CorsCheckResult<'a> {
    fn add_headers_to<'b>(
        &'a self,
        response: &'b mut HttpResponseBuilder,
    ) -> &'b mut HttpResponseBuilder {
        if let CorsCheckResult::ApprovedOrigin(origin) = self {
            response
                .append_header((ACCESS_CONTROL_ALLOW_ORIGIN, *origin))
                .append_header((ACCESS_CONTROL_MAX_AGE, "86400"))
                .append_header((ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"))
                .append_header(("Vary", ORIGIN.as_str()))
        } else {
            response
        }
    }

    pub fn with_headers(&'a self, mut response: HttpResponseBuilder) -> HttpResponseBuilder {
        self.add_headers_to(&mut response);
        response
    }
}
