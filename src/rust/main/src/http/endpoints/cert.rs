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

use crate::http::TokenCertificate;
use tiny_auth_business::cors::CorsLister;
use tiny_auth_web::cors::render_invalid_request;
use tiny_auth_web::cors::CorsCheckResult;
use tiny_auth_web::cors::CorsChecker;

use std::sync::Arc;

use actix_web::web::Data;
use actix_web::HttpRequest;
use actix_web::HttpResponse;

pub async fn get(
    request: HttpRequest,
    cors_lister: Data<Arc<dyn CorsLister>>,
    token_certificate: Data<TokenCertificate>,
) -> HttpResponse {
    match CorsChecker::new(cors_lister.get_ref().clone()).check(&request) {
        CorsCheckResult::IllegalOrigin => render_invalid_request(),
        approved @ (CorsCheckResult::ApprovedOrigin(_) | CorsCheckResult::NoOrigin) => approved
            .with_headers(HttpResponse::Ok())
            .body(token_certificate.0.clone()),
    }
}
