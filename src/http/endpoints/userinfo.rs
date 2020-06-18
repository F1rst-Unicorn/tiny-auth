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

use super::parse_bearer_authorization;
use crate::business::token::TokenValidator;

use actix_web::web::Data;
use actix_web::HttpRequest;
use actix_web::HttpResponse;

pub async fn handle(headers: HttpRequest, validator: Data<TokenValidator>) -> HttpResponse {
    let token = match headers.headers().get("Authorization") {
        Some(header) => match parse_bearer_authorization(header) {
            Some(token) => token,
            None => {
                return HttpResponse::Unauthorized()
                .header("www-authenticate", "error=\"invalid_request\", error_description=\"Invalid authorization header\"")
                .finish();
            }
        },
        None => {
            return HttpResponse::BadRequest()
                .header(
                    "www-authenticate",
                    "error=\"invalid_request\", error_description=\"Missing authorization header\"",
                )
                .finish();
        }
    };

    let token = match validator.validate(&token) {
        None => {
            return HttpResponse::Unauthorized()
                .header(
                    "www-authenticate",
                    "error=\"invalid_token\", error_description=\"Invalid token\"",
                )
                .finish();
        }
        Some(token) => token,
    };

    HttpResponse::Ok().json(token)
}
