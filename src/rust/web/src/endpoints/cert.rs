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

use crate::cors::render_invalid_request;
use crate::cors::CorsCheckResult;
use crate::cors::CorsChecker;
use actix_web::web::Data;
use actix_web::web::Path;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use serde_derive::Deserialize;
use std::sync::Arc;
use tiny_auth_business::cors::CorsLister;
use tracing::instrument;

use super::not_found;

#[derive(Deserialize)]
pub struct Index {
    index: usize,
}

#[derive(Clone)]
pub struct TokenCertificate(pub String);

#[instrument(skip_all, fields(transport = "http"))]
pub async fn get(
    request: HttpRequest,
    cors_lister: Data<Arc<dyn CorsLister>>,
    token_certificate: Data<Vec<TokenCertificate>>,
    index: Path<Index>,
) -> HttpResponse {
    match CorsChecker::new(cors_lister.get_ref().clone()).check(&request) {
        CorsCheckResult::IllegalOrigin => render_invalid_request(),
        approved @ (CorsCheckResult::ApprovedOrigin(_) | CorsCheckResult::NoOrigin) => {
            let index = index.into_inner().index;
            if index >= token_certificate.len() {
                not_found().await
            } else {
                approved
                    .with_headers(HttpResponse::Ok())
                    .body(token_certificate[index].0.clone())
            }
        }
    }
}
