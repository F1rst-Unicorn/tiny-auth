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

use std::collections::HashMap;

use actix_web::web;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;
use actix_web::Responder;
use actix_web::cookie::SameSite;

use actix_session::CookieSession;

use tera::Tera;
use tera::Context;
use tera::Result;
use tera::Value;

use crate::config;
use crate::store::memory::MemoryClientStore;
use crate::store::memory::MemoryUserStore;

use log::warn;

async fn index(state: web::Data<state::State>) -> impl Responder {
    let body = state.tera.render("base.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[actix_rt::main]
pub async fn run(web: config::Web) -> std::io::Result<()> {
    let bind = web.bind.clone();
    HttpServer::new(move || {

        let template_path = web.static_files.clone() + "/templates/";

        let mut tera = match Tera::new(&(template_path.clone() + "**/*")) {
            Ok(t) => t,
            Err(e) => {
                warn!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };

        tera.register_function("url", url_mapper);
        tera.register_function("translate", translator);
        tera.register_function("static", static_mapper);

        let state = state::State {
            tera: tera,
            client_store: Box::new(MemoryClientStore{}),
            user_store: Box::new(MemoryUserStore{}),
        };

        App::new()
            .data(state)
            .wrap(CookieSession::private(&[119; 32])
                // ^- encryption is only needed to avoid encoding problems
                .domain(&web.domain)
                .name("session")
                .path(web.path.as_ref().expect("no default given"))
                .secure(web.tls.is_some())
                .http_only(true)
                .same_site(SameSite::None)
                .max_age(web.session_timeout.expect("no default given"))
            )
            .service(
                web::scope(&web.path.as_ref().expect("no default given"))
                    .route("", web::get().to(index))
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

fn url_mapper(args: &HashMap<String, Value>) -> Result<Value> {
    match args.get("name") {
        Some(val) => Ok(val.clone()),
        None => Err("oops".into()),
    }
}

fn translator(args: &HashMap<String, Value>) -> Result<Value> {
    match args.get("term") {
        Some(val) => Ok(val.clone()),
        None => Err("oops".into()),
    }
}

fn static_mapper(args: &HashMap<String, Value>) -> Result<Value> {
    match args.get("name") {
        Some(val) => Ok(val.clone()),
        None => Err("oops".into()),
    }
}