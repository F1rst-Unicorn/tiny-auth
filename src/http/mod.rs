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

pub mod endpoints;
mod state;
mod tera;

use actix_web::web;
use actix_web::App;
use actix_web::HttpServer;
use actix_web::cookie::SameSite;

use actix_session::CookieSession;

use crate::config;
use crate::store::memory::MemoryClientStore;
use crate::store::memory::MemoryUserStore;
use crate::store::memory::MemoryAuthorizationCodeStore;

#[actix_rt::main]
pub async fn run(web: config::Web) -> std::io::Result<()> {
    let bind = web.bind.clone();

    let tera = tera::load_template_engine(&web.static_files);

    let state = web::Data::new(state::State {
        tera: tera,
        client_store: Box::new(MemoryClientStore{}),
        user_store: Box::new(MemoryUserStore{}),
        auth_code_store: Box::new(MemoryAuthorizationCodeStore{}),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(CookieSession::private(&[119; 32])
                // ^- encryption is only needed to avoid encoding problems
                .domain(&web.domain)
                .name("session")
                .path(web.path.as_ref().expect("no default given"))
                .secure(web.tls.is_some())
                .http_only(true)
                .same_site(SameSite::Strict)
                .max_age(web.session_timeout.expect("no default given"))
            )
            .service(
                web::scope(&web.path.as_ref().expect("no default given"))
                    .route("/authorize", web::get().to(endpoints::authorize::get))
                    .route("/authorize", web::post().to(endpoints::authorize::post))
                    .route("/token", web::post().to(endpoints::token::post))
                    .route("/userinfo", web::get().to(endpoints::userinfo::get))
                    .route("/authenticate", web::get().to(endpoints::authenticate::get))
                    .route("/authenticate", web::post().to(endpoints::authenticate::post))
                    .route("/consent", web::get().to(endpoints::consent::get))
                    .route("/consent", web::post().to(endpoints::consent::post))
            )
    })
    .bind(&bind)?
    .run()
    .await
}
