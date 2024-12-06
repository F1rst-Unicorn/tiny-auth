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
use serde_derive::Serialize;
use std::sync::Arc;
use tiny_auth_business::cors::CorsLister;
use tiny_auth_business::data::jwk::{Jwk, Jwks};
use tiny_auth_business::issuer_configuration::IssuerConfiguration;
use tiny_auth_business::store::ScopeStore;
use tracing::{instrument, warn};

#[derive(Serialize, Default)]
struct Response {
    #[serde(skip_serializing_if = "String::is_empty")]
    issuer: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    authorization_endpoint: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    token_endpoint: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    userinfo_endpoint: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    jwks_uri: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    registration_endpoint: String,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    response_types_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    response_modes_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    grant_types_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    acr_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    subject_types_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    id_token_signing_alg_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    id_token_encryption_alg_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    id_token_encryption_enc_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    userinfo_signing_alg_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    userinfo_encryption_alg_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    userinfo_encryption_enc_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_object_signing_alg_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_object_encryption_alg_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_object_encryption_enc_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_endpoint_auth_methods_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_endpoint_auth_signing_alg_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    display_values_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    claim_types_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    claims_supported: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty")]
    service_documentation: String,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    claims_locales_supported: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    ui_locales_supported: Vec<String>,

    claims_parameter_supported: bool,

    request_parameter_supported: bool,

    request_uri_parameter_supported: bool,

    require_request_uri_registration: bool,

    #[serde(skip_serializing_if = "String::is_empty")]
    op_policy_uri: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    op_tos_uri: String,
}

pub struct Handler {
    cors_lister: Arc<dyn CorsLister>,
    issuer_configuration: IssuerConfiguration,
    scope_store: Arc<dyn ScopeStore>,
}

#[instrument(skip_all, name = "discovery")]
pub async fn get(request: HttpRequest, handler: Data<Handler>) -> HttpResponse {
    handler.handle(request).await
}

impl Handler {
    async fn handle(&self, request: HttpRequest) -> HttpResponse {
        let scopes = self
            .scope_store
            .get_scope_names()
            .await
            .unwrap_or_else(|e| {
                warn!(%e, "failed to load scopes");
                Vec::default()
            });

        let response = Response {
            issuer: self.issuer_configuration.issuer_url.clone(),
            authorization_endpoint: self.issuer_configuration.issuer_url.clone() + "/authorize",
            token_endpoint: self.issuer_configuration.issuer_url.clone() + "/token",
            userinfo_endpoint: self.issuer_configuration.issuer_url.clone() + "/userinfo",
            jwks_uri: self.issuer_configuration.issuer_url.clone() + "/jwks",
            scopes_supported: scopes,
            response_types_supported: vec![
                "code".to_owned(),
                "token".to_owned(),
                "id_token".to_owned(),
                "code id_token".to_owned(),
                "token id_token".to_owned(),
                "code token".to_owned(),
                "code token id_token".to_owned(),
            ],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "implicit".to_owned(),
                "client_credentials".to_owned(),
                "password".to_owned(),
                "refresh_token".to_owned(),
            ],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec![
                "HS256".to_owned(),
                "HS384".to_owned(),
                "HS512".to_owned(),
                "ES256".to_owned(),
                "ES384".to_owned(),
                "RS256".to_owned(),
                "RS384".to_owned(),
                "RS512".to_owned(),
                "PS256".to_owned(),
                "PS384".to_owned(),
                "PS512".to_owned(),
            ],

            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_owned(),
                "client_secret_post".to_owned(),
                "client_secret_jwt".to_owned(),
                "private_key_jwt".to_owned(),
            ],

            claims_supported: vec![
                "iss".to_owned(),
                "sub".to_owned(),
                "aud".to_owned(),
                "exp".to_owned(),
                "iat".to_owned(),
                "auth_time".to_owned(),
                "nonce".to_owned(),
                "acr".to_owned(),
                "amr".to_owned(),
                "azp".to_owned(),
            ],
            service_documentation: env!("CARGO_PKG_HOMEPAGE").to_owned(),
            claims_locales_supported: vec!["en".to_owned()],
            ui_locales_supported: vec!["en".to_owned()],
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            ..Default::default()
        };

        render_cors_result(self.cors_lister.clone(), &request, response)
    }
}

pub mod inject {
    use crate::endpoints::discovery::Handler;
    use std::sync::Arc;
    use tiny_auth_business::cors::CorsLister;
    use tiny_auth_business::issuer_configuration::IssuerConfiguration;
    use tiny_auth_business::store::ScopeStore;

    pub fn handler(
        cors_lister: Arc<dyn CorsLister>,
        issuer_configuration: IssuerConfiguration,
        scope_store: Arc<dyn ScopeStore>,
    ) -> Handler {
        Handler {
            cors_lister,
            issuer_configuration,
            scope_store,
        }
    }
}

#[derive(Serialize)]
pub struct JwksWebView<'a> {
    pub keys: Vec<&'a Jwk>,
}

impl<'a> From<&'a Jwks> for JwksWebView<'a> {
    fn from(value: &'a Jwks) -> Self {
        let mut keys = vec![&value.first_key];
        keys.extend(value.keys.iter());
        Self { keys }
    }
}

#[instrument(skip_all)]
pub async fn jwks(
    jwks: Data<Jwks>,
    cors_lister: Data<Arc<dyn CorsLister>>,
    request: HttpRequest,
) -> HttpResponse {
    render_cors_result(
        cors_lister.get_ref().clone(),
        &request,
        JwksWebView::from(jwks.as_ref()),
    )
}
