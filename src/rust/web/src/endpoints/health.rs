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

use crate::endpoints::render_cors_result;
use actix_web::web::Data;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tiny_auth_business::cors::CorsLister;
use tiny_auth_business::health::HealthChecker;
use tracing::instrument;

#[derive(Serialize)]
struct Health {
    ok: bool,
    #[serde(flatten)]
    checks: HashMap<String, bool>,
}

#[instrument(skip_all, name = "health")]
pub async fn get(
    request: HttpRequest,
    cors_lister: Data<Arc<dyn CorsLister>>,
    handler: Data<HealthChecker>,
) -> HttpResponse {
    let results = handler.execute_all().await;
    let summary = results.iter().all(|v| v.state);
    let health = Health {
        ok: summary,
        checks: results.into_iter().map(|v| (v.name, v.state)).collect(),
    };
    render_cors_result(cors_lister.get_ref().clone(), &request, health)
}
