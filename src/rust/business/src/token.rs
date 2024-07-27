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

use crate::client::Client;
use crate::clock::Clock;
use crate::issuer_configuration::IssuerConfiguration;
use crate::jwk::Jwk;
use crate::scope::merge;
use crate::scope::Scope;
use crate::template::scope::ScopeContext;
use crate::template::Templater;
use crate::user::User;
use chrono::Duration;
use jsonwebtoken::decode;
use jsonwebtoken::encode;
use jsonwebtoken::errors::Result;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::Validation;
use serde::de::DeserializeOwned;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, instrument};
use tracing::{error, warn};

/// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "sub")]
    pub subject: String,

    #[serde(rename = "aud")]
    audience: Audience,

    #[serde(rename = "exp")]
    expiration: i64,

    #[serde(rename = "iat")]
    issuance_time: i64,

    #[serde(rename = "auth_time")]
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    auth_time: i64,

    #[serde(rename = "nonce")]
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub nonce: String,

    #[serde(rename = "acr")]
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    authentication_context_class_reference: String,

    #[serde(rename = "amr")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    authentication_methods_request: Vec<String>,

    #[serde(rename = "azp")]
    pub authorized_party: String,

    #[serde(flatten)]
    scope_attributes: Value,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde needs this API
fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl Token {
    pub fn set_nonce(&mut self, nonce: Option<String>) {
        if let Some(nonce) = nonce {
            self.nonce = nonce;
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Several(Vec<String>),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RefreshToken {
    #[serde(rename = "iss")]
    pub issuer: String,

    pub access_token: Token,

    #[serde(rename = "exp")]
    pub expiration: i64,

    pub scopes: Vec<String>,
}

#[derive(Clone)]
pub struct TokenCreator {
    key: EncodingKey,

    issuer: IssuerConfiguration,

    jwk: Jwk,

    clock: Arc<dyn Clock>,

    token_expiration: Duration,

    refresh_token_expiration: Duration,

    templater: Arc<dyn for<'a> Templater<ScopeContext<'a>>>,
}

impl TokenCreator {
    pub fn new(
        key: EncodingKey,
        issuer: IssuerConfiguration,
        jwk: Jwk,
        clock: Arc<dyn Clock>,
        token_expiration: Duration,
        refresh_token_expiration: Duration,
        templater: Arc<dyn for<'a> Templater<ScopeContext<'a>>>,
    ) -> Self {
        Self {
            key,
            issuer,
            jwk,
            clock,
            token_expiration,
            refresh_token_expiration,
            templater,
        }
    }

    #[instrument(skip_all)]
    pub fn build_token(
        &self,
        user: &User,
        client: &Client,
        scopes: &[Scope],
        auth_time: i64,
    ) -> Token {
        let now = self.clock.now();
        let mut result = Token {
            issuer: self.issuer.issuer_url.to_string(),
            subject: user.name.clone(),
            audience: Audience::Single(client.client_id.clone()),
            expiration: (now + self.token_expiration).timestamp(),
            issuance_time: now.timestamp(),
            auth_time,
            nonce: "".to_string(),
            authentication_context_class_reference: "".to_string(),
            authentication_methods_request: vec![],
            authorized_party: client.client_id.to_string(),
            scope_attributes: Value::Null,
        };

        debug!("issuing token");
        let mut claim_collector = Value::Object(Default::default());
        for scope in scopes {
            let claims = match scope.generate_claims(self.templater.clone(), user, client) {
                Err(_) => {
                    warn!(
                        scope = scope.name,
                        "failed to generate claims. Skipping",
                    );
                    continue;
                }
                Ok(c) => c,
            };

            claim_collector = match merge(claim_collector.clone(), claims) {
                Err(_) => {
                    error!(
                        "Failed to merge claims for scope '{}'. Skipping scope",
                        scope.name
                    );
                    continue;
                }
                Ok(c) => c,
            };
        }

        result.scope_attributes = claim_collector;
        result
    }

    pub fn expiration(&self) -> Duration {
        self.token_expiration
    }

    pub fn renew(&self, token: &mut Token) {
        debug!("renewing token");
        let now = self.clock.now();
        token.issuance_time = now.clone().timestamp();
        token.expiration = (now + self.token_expiration).timestamp();
    }

    pub fn build_refresh_token(&self, mut token: Token, scopes: &[Scope]) -> RefreshToken {
        debug!("issuing refresh token");
        token.issuer = self.issuer.issuer_url.to_string();
        RefreshToken {
            issuer: token.issuer.clone(),
            expiration: token.issuance_time + self.refresh_token_expiration.num_seconds(),
            access_token: token,
            scopes: scopes.iter().map(|v| v.name.to_string()).collect(),
        }
    }

    pub fn finalize(&self, token: Token) -> Result<String> {
        let mut header = Header::new(self.issuer.algorithm);
        header.kid = Some(self.jwk.key_id.clone());
        header.jku = Some(self.issuer.jwks());
        encode(&header, &token, &self.key)
    }

    pub fn finalize_refresh_token(&self, token: RefreshToken) -> Result<String> {
        let mut header = Header::new(self.issuer.algorithm);
        header.kid = Some(self.jwk.key_id.clone());
        header.jku = Some(self.issuer.jwks());
        encode(&header, &token, &self.key)
    }
}

#[derive(Clone)]
pub struct TokenValidator {
    key: DecodingKey,

    validation: Validation,
}

impl TokenValidator {
    pub fn new(key: DecodingKey, algorithm: Algorithm, issuer: String) -> Self {
        let mut validation = Validation::new(algorithm);
        validation.leeway = 5;
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_issuer(&[issuer]);
        Self { key, validation }
    }

    pub fn validate<T: DeserializeOwned>(&self, token: &str) -> Option<T> {
        debug!("validating token");
        decode::<T>(token, &self.key, &self.validation)
            .map(|v| v.claims)
            .map_err(|e| {
                debug!(%e, "token validation failed");
                e
            })
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;

    #[test]
    pub fn deserialise_single_audience() {
        let input = r#"{
            "iss":"",
            "sub":"",
            "aud":"audience",
            "exp":1,
            "iat":1,
            "auth_time":1,
            "nonce":"",
            "acr":"",
            "amr":[],
            "azp":""
        }"#;

        match from_str::<Token>(input) {
            Err(_) => unreachable!(),
            Ok(token) => {
                assert_eq!(Audience::Single("audience".to_string()), token.audience);
            }
        }
    }

    #[test]
    pub fn deserialise_list_audience() {
        let input = r#"{
            "iss":"",
            "sub":"",
            "aud":["audience1","audience2"],
            "exp":1,
            "iat":1,
            "auth_time":1,
            "nonce":"",
            "acr":"",
            "amr":[],
            "azp":""
        }"#;

        match from_str::<Token>(input) {
            Err(_) => unreachable!(),
            Ok(token) => {
                assert_eq!(
                    Audience::Several(vec!["audience1".to_string(), "audience2".to_string()]),
                    token.audience
                );
            }
        }
    }
}
