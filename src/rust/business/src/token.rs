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

use crate::clock::Clock;
use crate::data::client::Client;
use crate::data::jwk::Jwk;
use crate::data::scope::Scope;
use crate::data::scope::{merge, Destination};
use crate::data::user::User;
use crate::issuer_configuration::IssuerConfiguration;
use crate::template::scope::ScopeContext;
use crate::template::Templater;
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
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::{debug, instrument};
use tracing::{error, warn};

/// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Token<T> {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "sub")]
    pub subject: String,

    #[serde(rename = "aud")]
    audience: Audience,

    #[serde(rename = "exp")]
    expiration: i64,

    #[serde(rename = "iat")]
    pub issuance_time: i64,

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

    #[serde(rename = "scopes")]
    pub scopes: Vec<String>,

    #[serde(flatten)]
    scope_attributes: Value,

    #[serde(skip)]
    token_type: PhantomData<T>,
}

pub trait TokenType: Default + Clone {}

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct Access;

impl TokenType for Access {}

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct Id;

impl TokenType for Id {}

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct Userinfo;

impl TokenType for Userinfo {}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(transparent)]
pub struct EncodedAccessToken(String);

impl From<EncodedAccessToken> for String {
    fn from(value: EncodedAccessToken) -> Self {
        value.0
    }
}

impl AsRef<str> for EncodedAccessToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(transparent)]
pub struct EncodedIdToken(String);

impl From<EncodedIdToken> for String {
    fn from(value: EncodedIdToken) -> Self {
        value.0
    }
}

impl AsRef<str> for EncodedIdToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde needs this API
fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl<T> Token<T> {
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

    #[serde(rename = "sub")]
    pub subject: String,

    #[serde(rename = "nonce")]
    pub nonce: String,

    #[serde(rename = "azp")]
    pub authorized_party: String,

    #[serde(rename = "exp")]
    pub expiration: i64,

    #[serde(rename = "auth_time")]
    pub auth_time: i64,

    pub scopes: Vec<String>,
}

impl RefreshToken {
    pub fn set_nonce(&mut self, nonce: Option<String>) {
        if let Some(nonce) = nonce {
            self.nonce = nonce;
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Eq, PartialEq)]
#[serde(transparent)]
pub struct EncodedRefreshToken(String);

impl EncodedRefreshToken {
    /// # Safety
    /// Use only to reconstruct an instance that was formerly validated by one of the safe
    /// constructors, e.g. when reinstantiating it from a persisted form.
    pub unsafe fn from_parts(token: String) -> Self {
        Self(token)
    }
}

impl From<EncodedRefreshToken> for String {
    fn from(value: EncodedRefreshToken) -> Self {
        value.0
    }
}

impl AsRef<str> for EncodedRefreshToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
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
    pub fn build_token<T: Default + Into<Destination>>(
        &self,
        user: &User,
        client: &Client,
        scopes: &[Scope],
        auth_time: i64,
    ) -> Token<T> {
        let now = self.clock.now();
        let mut result = Token {
            issuer: self.issuer.issuer_url.to_owned(),
            subject: user.name.clone(),
            audience: Audience::Single(client.client_id.clone()),
            expiration: (now + self.token_expiration).timestamp(),
            issuance_time: now.timestamp(),
            auth_time,
            nonce: "".to_owned(),
            authentication_context_class_reference: "".to_owned(),
            authentication_methods_request: vec![],
            authorized_party: client.client_id.to_owned(),
            scopes: scopes.iter().map(|v| v.name.clone()).collect(),
            scope_attributes: Value::Null,
            token_type: PhantomData,
        };

        debug!("issuing token");
        let mut claim_collector = Value::Object(Default::default());
        for scope in scopes {
            let claims = match scope.generate_claims(
                self.templater.clone(),
                user,
                client,
                T::default().into(),
            ) {
                Err(e) => {
                    warn!(%e, scope = scope.name, "failed to generate claims. Skipping",);
                    continue;
                }
                Ok(c) => c,
            };

            claim_collector = match merge(claim_collector.clone(), claims) {
                Err(e) => {
                    error!(%e,
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

    pub fn renew<T>(&self, token: &mut Token<T>) {
        debug!("renewing token");
        let now = self.clock.now();
        token.issuance_time = now.clone().timestamp();
        token.expiration = (now + self.token_expiration).timestamp();
    }

    pub fn build_fresh_refresh_token(
        &self,
        scopes: &[Scope],
        subject: &str,
        authorized_party: &str,
        auth_time: i64,
    ) -> RefreshToken {
        debug!("issuing refresh token");
        self.build_refresh_token(
            self.clock.now().timestamp(),
            scopes,
            subject,
            authorized_party,
            auth_time,
        )
    }

    pub fn build_refresh_token(
        &self,
        issuance_time: i64,
        scopes: &[Scope],
        subject: &str,
        authorized_party: &str,
        auth_time: i64,
    ) -> RefreshToken {
        debug!("issuing refresh token");
        RefreshToken {
            issuer: self.issuer.issuer_url.to_owned(),
            subject: subject.to_owned(),
            nonce: "".to_owned(),
            authorized_party: authorized_party.to_owned(),
            expiration: issuance_time + self.refresh_token_expiration.num_seconds(),
            auth_time,
            scopes: scopes.iter().map(|v| v.name.to_owned()).collect(),
        }
    }

    pub fn finalize_access_token(&self, token: Token<Access>) -> Result<EncodedAccessToken> {
        let mut header = Header::new(self.issuer.algorithm);
        header.kid = Some(self.jwk.key_id.clone());
        header.jku = Some(self.issuer.jwks());
        Ok(EncodedAccessToken(encode(&header, &token, &self.key)?))
    }

    pub fn finalize_id_token(&self, token: Token<Id>) -> Result<EncodedIdToken> {
        let mut header = Header::new(self.issuer.algorithm);
        header.kid = Some(self.jwk.key_id.clone());
        header.jku = Some(self.issuer.jwks());
        Ok(EncodedIdToken(encode(&header, &token, &self.key)?))
    }

    pub fn finalize_refresh_token(&self, token: RefreshToken) -> Result<EncodedRefreshToken> {
        let mut header = Header::new(self.issuer.algorithm);
        header.kid = Some(self.jwk.key_id.clone());
        header.jku = Some(self.issuer.jwks());
        Ok(EncodedRefreshToken(encode(&header, &token, &self.key)?))
    }
}

#[derive(Clone)]
pub struct TokenValidator {
    key: DecodingKey,

    validation: Validation,
}

impl TokenValidator {
    pub const TINY_AUTH_FRONTEND_CLIENT_ID: &'static str = "tiny-auth-frontend";

    pub fn new(key: DecodingKey, algorithm: Algorithm, issuer: String) -> Self {
        let mut validation = Validation::new(algorithm);
        validation.leeway = 5;
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_issuer(&[issuer]);
        Self { key, validation }
    }

    pub fn new_for_own_api(key: DecodingKey, algorithm: Algorithm, issuer: String) -> Self {
        let mut validation = Validation::new(algorithm);
        validation.leeway = 5;
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_audience(&[Self::TINY_AUTH_FRONTEND_CLIENT_ID]);
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

    pub fn validate_access_token(&self, token: EncodedAccessToken) -> Option<Token<Access>> {
        self.validate(token.as_ref())
    }

    pub fn validate_id_token(&self, token: EncodedIdToken) -> Option<Token<Id>> {
        self.validate(token.as_ref())
    }

    pub fn validate_refresh_token(&self, token: EncodedRefreshToken) -> Option<RefreshToken> {
        self.validate(token.as_ref())
    }
}
