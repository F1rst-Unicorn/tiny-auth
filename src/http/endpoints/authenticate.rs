/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The cinit developers
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

use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;
use actix_web::web;

use tera::Context;

use crate::http::state::State;

pub async fn get(request: HttpRequest, state: web::Data<State>) -> impl Responder {
    let body = state.tera.render("authenticate.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn post(request: HttpRequest) -> impl Responder {
    HttpResponse::Ok().finish()
}
