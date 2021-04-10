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
pub mod state;
mod tera;

use crate::config::Config;
use crate::runtime::Error;
use endpoints::*;

use rocket::config::TlsConfig;
use rocket::routes;
use rocket::Rocket;
use rocket::Shutdown;

use rocket_contrib::serve::StaticFiles;

pub fn build(config: Config) -> Result<(Rocket, Shutdown), Error> {
    let constructor = state::Constructor::new(&config)?;

    let tera = constructor
        .get_template_engine()
        .ok_or(Error::LoggedBeforeError)?;
    let token_certificate = constructor.get_public_key();
    let token_creator = constructor.build_token_creator()?;
    let token_validator = constructor.build_token_validator()?;
    let user_store = constructor
        .get_user_store()
        .ok_or(Error::LoggedBeforeError)?;
    let client_store = constructor
        .get_client_store()
        .ok_or(Error::LoggedBeforeError)?;
    let scope_store = constructor
        .get_scope_store()
        .ok_or(Error::LoggedBeforeError)?;
    let auth_code_store = constructor
        .build_auth_code_store()
        .ok_or(Error::LoggedBeforeError)?;
    let authenticator = constructor
        .build_authenticator()
        .ok_or(Error::LoggedBeforeError)?;
    let issuer_config = constructor.get_issuer_config();
    let jwks = constructor.build_jwks()?;
    let cookie_builder = constructor.get_cookie_builder();

    std::mem::drop(constructor);

    if config.web.secret_key.len() < 32 {
        return Err(Error::SecretTooShort);
    }

    let mut rocket_config = rocket::Config::release_default();
    rocket_config.ctrlc = false;
    rocket_config.keep_alive = 60;
    rocket_config.address = config.web.bind.address.parse()?;
    rocket_config.port = config.web.bind.port;
    rocket_config.workers = config.web.workers.unwrap_or(rocket_config.workers);
    rocket_config.secret_key =
        rocket::config::SecretKey::derive_from(config.web.secret_key.as_bytes());
    rocket_config.log_level = rocket::config::LogLevel::Debug;

    if let Some(config) = config.web.tls {
        let tls_config = TlsConfig::from_paths(config.certificate, config.key);
        rocket_config.tls = Some(tls_config);
    }

    let base_path = config.web.path;

    let rocket = rocket::custom(rocket_config)
        .manage(tera)
        .manage(authenticator)
        .manage(client_store)
        .manage(scope_store)
        .manage(user_store)
        .manage(auth_code_store)
        .manage(token_creator)
        .manage(token_validator)
        .manage(issuer_config)
        .manage(jwks)
        .manage(cookie_builder);

    let rocket = mount_paths(rocket, &base_path, &config.web.static_files);

    let shutdown = rocket.shutdown();

    Ok((rocket, shutdown))
}

fn mount_paths(rocket: Rocket, base_path: &str, static_base: &str) -> Rocket {
    rocket
        .mount(
            base_path.to_string() + "/static/css",
            StaticFiles::from(static_base.to_string() + "/css"),
        )
        .mount(
            base_path.to_string() + "/static/img",
            StaticFiles::from(static_base.to_string() + "/img"),
        )
        .mount(
            base_path.to_string() + "/.well-known/openid-configuration",
            routes![discovery::get],
        )
        .mount(base_path.to_string() + "/jwks", routes![discovery::jwks])
        .mount(
            base_path.to_string() + "/authorize",
            routes![authorize::get, authorize::post],
        )
        .mount(base_path.to_string() + "/health", routes![health::get])
}

#[cfg(test)]
pub mod tests {

    use crate::http::state::tests::*;

    use rocket::local::blocking::Client;
    use rocket::Rocket;

    pub fn build_client() -> Client {
        Client::tracked(build_rocket()).expect("Failed to build client")
    }

    pub fn build_rocket() -> Rocket {
        super::mount_paths(build_rocket_state(), "", "static")
    }

    fn build_rocket_state() -> Rocket {
        let mut rocket_config = rocket::Config::debug_default();
        rocket_config.log_level = rocket::config::LogLevel::Debug;
        rocket_config.secret_key = rocket::config::SecretKey::from(
            "oYlv4KTjQGqxwVaBgTMj3andosEfZJfZOtp2TPEKIJMIiHGb7FYnY1jLde5HeyjO0hw8ua47SWtT1Q9UCAgcc"
                .as_bytes(),
        );
        rocket::custom(rocket_config)
            .manage(build_test_tera())
            .manage(build_test_authenticator())
            .manage(build_test_client_store())
            .manage(build_test_scope_store())
            .manage(build_test_user_store())
            .manage(build_test_auth_code_store())
            .manage(build_test_token_creator())
            .manage(build_test_token_validator())
            .manage(build_test_issuer_config())
            .manage(build_test_cookie_builder())
    }
}

/*
fn parked(config: Config) -> _ {

    let server = HttpServer::new(move || {
        App::new()
            .wrap(DefaultHeaders::new().header("Cache-Control", "no-store"))
            .wrap(DefaultHeaders::new().header("Pragma", "no-cache"))
            .service(
                web::scope(&rocket_config.web.path.as_ref().unwrap())
                    .route("/token", post().to(endpoints::token::post))
                    .route("/token", all().to(endpoints::method_not_allowed))
                    .route("/userinfo", get().to(endpoints::userinfo::get))
                    .route("/userinfo", post().to(endpoints::userinfo::post))
                    .route("/userinfo", all().to(endpoints::method_not_allowed))
                    .route("/authenticate", get().to(endpoints::authenticate::get))
                    .route("/authenticate", post().to(endpoints::authenticate::post))
                    .route("/authenticate", all().to(endpoints::method_not_allowed))
                    .route(
                        "/authenticate/cancel",
                        get().to(endpoints::authenticate::cancel),
                    )
                    .route(
                        "/authenticate/cancel",
                        all().to(endpoints::method_not_allowed),
                    )
                    .route(
                        "/select_account",
                        get().to(endpoints::authenticate::select_account),
                    )
                    .route("/select_account", all().to(endpoints::method_not_allowed))
                    .route("/consent", get().to(endpoints::consent::get))
                    .route("/consent", post().to(endpoints::consent::post))
                    .route("/consent", all().to(endpoints::method_not_allowed))
                    .route("/consent/cancel", get().to(endpoints::consent::cancel))
                    .route("/consent/cancel", all().to(endpoints::method_not_allowed))
                    .route(
                        "/cert",
                        get().to(move || HttpResponse::Ok().body(token_certificate.clone())),
                    )
                    .route("/cert", all().to(endpoints::method_not_allowed))
            )
    });
}
*/
