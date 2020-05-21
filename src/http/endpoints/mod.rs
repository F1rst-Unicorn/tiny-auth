pub mod authenticate;
pub mod token;
pub mod authorize;
pub mod userinfo;
pub mod consent;

use crate::protocol::oauth2::ProtocolError;

use actix_web::HttpResponse;

use url::Url;

pub fn missing_parameter(redirect_uri: &str, error: ProtocolError, description: &str, state: &Option<String>) -> HttpResponse {
    let mut url = Url::parse(redirect_uri).expect("should have been validated upon registration");

    url.query_pairs_mut()
        .append_pair("error", &format!("{}", error))
        .append_pair("error_description", description);

    if let Some(state) = state {
        url.query_pairs_mut()
            .append_pair("state", state);
    }

    HttpResponse::TemporaryRedirect()
        .set_header("Location", url.as_str())
        .finish()
}

pub fn server_error(tera: &tera::Tera) -> HttpResponse {
    let body = tera.render("500.html.j2", &tera::Context::new());
    match body {
        Ok(body) => HttpResponse::InternalServerError().body(body),
        Err(e) => {
            log::warn!("{}", e);
            HttpResponse::InternalServerError().finish()
        }
    } 
}