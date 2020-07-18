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

use crate::domain::IssuerConfiguration;
use crate::store::ScopeStore;

use std::sync::Arc;

use actix_web::web::Data;
use actix_web::HttpResponse;

use serde_derive::Serialize;

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

pub async fn get(
    config: Data<IssuerConfiguration>,
    scopes: Data<Arc<dyn ScopeStore>>,
) -> HttpResponse {
    let response = Response {
        issuer: config.issuer_url.clone(),
        authorization_endpoint: config.issuer_url.clone() + "/authorize",
        token_endpoint: config.issuer_url.clone() + "/token",
        userinfo_endpoint: config.issuer_url.clone() + "/userinfo",
        jwks_uri: config.issuer_url.clone() + "/jwks",
        scopes_supported: scopes.get_scope_names(),
        response_types_supported: vec![
            "code".to_string(),
            "token".to_string(),
            "id_token".to_string(),
            "code id_token".to_string(),
            "token id_token".to_string(),
            "code token".to_string(),
            "code token id_token".to_string(),
        ],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "implicit".to_string(),
            "client_credentials".to_string(),
            "password".to_string(),
            "refresh_token".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec![
            "HS256".to_string(),
            "HS384".to_string(),
            "HS512".to_string(),
            "ES256".to_string(),
            "ES384".to_string(),
            "RS256".to_string(),
            "RS384".to_string(),
            "RS512".to_string(),
            "PS256".to_string(),
            "PS384".to_string(),
            "PS512".to_string(),
        ],

        token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_string()],

        claims_supported: vec![
            "iss".to_string(),
            "sub".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "auth_time".to_string(),
            "nonce".to_string(),
            "acr".to_string(),
            "amr".to_string(),
            "azp".to_string(),
        ],
        service_documentation: env!("CARGO_PKG_HOMEPAGE").to_string(),
        claims_locales_supported: vec!["en".to_string()],
        ui_locales_supported: vec!["en".to_string()],
        claims_parameter_supported: false,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        ..Default::default()
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .json(response)
}

#[derive(Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct Jwk {
    #[serde(rename = "kty")]
    key_type: String,

    #[serde(rename = "use")]
    usage: String,

    #[serde(rename = "x5u")]
    url: String,
}

pub async fn jwks(config: Data<IssuerConfiguration>) -> HttpResponse {
    let response = Jwks {
        keys: vec![Jwk {
            key_type: config.algorithm.clone(),
            usage: "sig".to_string(),
            url: config.issuer_url.clone() + "/cert",
        }],
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .json(response)
}
