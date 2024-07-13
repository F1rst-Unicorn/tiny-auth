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

use crate::authenticator::Authenticator;
use crate::authenticator::Error::WrongCredentials;
use crate::client::Client;
use crate::issuer_configuration::IssuerConfiguration;
use crate::oauth2;
use crate::oauth2::ClientType;
use crate::oauth2::GrantType;
use crate::pkce::{CodeChallenge, CodeVerifier};
use crate::scope::parse_scope_names;
use crate::scope::Scope;
use crate::store::ScopeStore;
use crate::store::UserStore;
use crate::store::AUTH_CODE_LIFE_TIME;
use crate::store::{AuthorizationCodeResponse, ClientStore};
use crate::store::{AuthorizationCodeStore, ValidationRequest};
use crate::token::RefreshToken;
use crate::token::Token;
use crate::token::TokenCreator;
use crate::token::TokenValidator;
use crate::user::User;
use chrono::offset::Local;
use chrono::Duration;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use serde_derive::Deserialize;
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::iter::FromIterator;
use std::sync::Arc;
use tracing::{debug, instrument, Level};
use tracing::{span, warn};

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Deserialize)]
struct ClientAssertion {
    #[serde(rename = "iss")]
    #[allow(dead_code)]
    issuer: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "aud")]
    #[allow(dead_code)]
    audience: String,

    #[serde(rename = "jti")]
    #[allow(dead_code)]
    id: String,

    #[serde(rename = "exp")]
    #[allow(dead_code)]
    expiration_time: i64,

    #[serde(rename = "iat")]
    #[allow(dead_code)]
    issuance_time: i64,
}

#[derive(Default)]
pub struct Request {
    pub basic_authentication: Option<(String, String)>,
    pub grant_type: GrantType,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub refresh_token: Option<String>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
    pub pkce_verifier: Option<String>,
}

#[derive(Clone)]
pub struct Handler {
    client_store: Arc<dyn ClientStore>,
    user_store: Arc<dyn UserStore>,
    auth_code_store: Arc<dyn AuthorizationCodeStore>,
    token_creator: TokenCreator,
    authenticator: Arc<Authenticator>,
    token_validator: Arc<TokenValidator>,
    scope_store: Arc<dyn ScopeStore>,
    issuer_configuration: IssuerConfiguration,
}

impl Handler {
    #[instrument(level = Level::DEBUG, skip_all, fields(
        client = request.client_id,
        pkce = request.pkce_verifier.is_some(),
        grant_type = ?request.grant_type))]
    pub async fn grant_tokens(
        &self,
        request: Request,
    ) -> Result<(String, Option<String>, Vec<Scope>), Error> {
        let (token, scopes, generate_refresh_token) = self.grant_token(request).await?;

        let encoded_token = match self.token_creator.finalize(token.clone()) {
            Err(e) => {
                debug!(%e, "failed to encode token");
                return Err(Error::TokenEncodingFailed);
            }
            Ok(token) => token,
        };
        let refresh_token = if generate_refresh_token {
            match self
                .token_creator
                .finalize_refresh_token(self.token_creator.build_refresh_token(token, &scopes))
            {
                Err(e) => {
                    debug!(%e, "failed to encode refresh token");
                    return Err(Error::RefreshTokenEncodingFailed);
                }
                token => token.ok(),
            }
        } else {
            None
        };

        Ok((encoded_token, refresh_token, scopes))
    }

    async fn grant_token(&self, request: Request) -> Result<(Token, Vec<Scope>, bool), Error> {
        match request.grant_type {
            GrantType::RefreshToken => self.grant_with_refresh_token(request).await,
            _ => {
                let (user, client, scopes, auth_time, nonce) = match request.grant_type {
                    GrantType::AuthorizationCode => {
                        self.grant_with_authorization_code(request).await?
                    }
                    GrantType::ClientCredentials => self
                        .grant_with_client_credentials(request)
                        .await
                        .map(|(a, b, c, d)| (a, b, c, d, None))?,
                    GrantType::Password => self
                        .grant_with_password(request)
                        .await
                        .map(|(a, b, c, d)| (a, b, c, d, None))?,
                    _ => {
                        return Err(Error::UnsupportedGrantType);
                    }
                };

                let generate_refresh_token =
                    matches!(client.client_type, ClientType::Confidential { .. });

                let _guard = span!(Level::DEBUG, "cid", user = user.name).entered();
                let mut token = self
                    .token_creator
                    .build_token(&user, &client, &scopes, auth_time);
                token.set_nonce(nonce);

                Ok((token, scopes, generate_refresh_token))
            }
        }
    }

    async fn grant_with_authorization_code(
        &self,
        request: Request,
    ) -> Result<(User, Client, Vec<Scope>, i64, Option<String>), Error> {
        request
            .redirect_uri
            .as_ref()
            .ok_or(Error::MissingRedirectUri)?;
        let code = request
            .code
            .as_ref()
            .ok_or(Error::MissingAuthorizationCode)?;
        let client = match self.authenticate_client(&request).await {
            Err(_) => {
                let client_id = &request.client_id.as_ref().ok_or(Error::MissingClientId)?;
                let client = self.client_store.get(client_id).await.map_err(|e| {
                    debug!(%e, "client not found");
                    Error::WrongClientIdOrPassword
                })?;

                if let ClientType::Confidential { .. } = client.client_type {
                    return Err(Error::ConfidentialClientMustAuthenticate);
                }

                client
            }
            Ok(client) => client,
        };

        let record = self
            .auth_code_store
            .validate(ValidationRequest {
                client_id: &client.client_id,
                authorization_code: code,
                validation_time: Local::now(),
            })
            .await
            .ok_or_else(|| {
                debug!(%code, "No authorization code found");
                Error::InvalidAuthorizationCode
            })?;

        self.grant_from_authorization_code_record(request, client, record)
            .await
    }

    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(user = record.username))]
    async fn grant_from_authorization_code_record(
        &self,
        request: Request,
        client: Client,
        record: AuthorizationCodeResponse,
    ) -> Result<(User, Client, Vec<Scope>, i64, Option<String>), Error> {
        let redirect_uri_from_request = request
            .redirect_uri
            .as_ref()
            .ok_or(Error::MissingRedirectUri)?;
        if &record.redirect_uri != redirect_uri_from_request {
            debug!(
                expected = record.redirect_uri,
                actual = request.redirect_uri,
                "redirect_uri is wrong"
            );
            return Err(Error::InvalidAuthorizationCode);
        }

        if record.stored_duration > Duration::minutes(AUTH_CODE_LIFE_TIME) {
            debug!("code has expired");
            return Err(Error::InvalidAuthorizationCode);
        }

        if let Some(challenge) = record.pkce_challenge {
            verify_pkce(challenge, request.pkce_verifier)?;
        }

        let user = self
            .user_store
            .get(&record.username)
            .await
            .map_err(|e| match e {
                crate::user::Error::NotFound => {
                    debug!("user not found");
                    Error::WrongUsernameOrPassword(format!("{}", WrongCredentials))
                }
                crate::user::Error::BackendError
                | crate::user::Error::BackendErrorWithContext(_) => Error::AuthenticationFailed,
            })?;

        let scopes = self.scope_store.get_all(&parse_scope_names(&record.scopes));

        Ok((
            user,
            client,
            scopes,
            record.authentication_time.timestamp(),
            record.nonce,
        ))
    }

    async fn grant_with_client_credentials(
        &self,
        request: Request,
    ) -> Result<(User, Client, Vec<Scope>, i64), Error> {
        let client = self.authenticate_client(&request).await?;
        let allowed_scopes = BTreeSet::from_iter(client.allowed_scopes.clone());
        let requested_scopes = match &request.scope {
            None => Default::default(),
            Some(scopes) => BTreeSet::from_iter(parse_scope_names(scopes)),
        };

        let scopes = allowed_scopes
            .intersection(&requested_scopes)
            .map(|v| self.scope_store.get(v))
            .map(Option::unwrap)
            .collect();

        Ok((
            client.clone().try_into().unwrap(),
            client,
            scopes,
            Local::now().timestamp(),
        ))
    }

    async fn grant_with_password(
        &self,
        request: Request,
    ) -> Result<(User, Client, Vec<Scope>, i64), Error> {
        let username = &request.username.as_ref().ok_or(Error::MissingUsername)?;
        self.grant_with_password_for_user(&request, username).await
    }

    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(user = username))]
    async fn grant_with_password_for_user(
        &self,
        request: &Request,
        username: &String,
    ) -> Result<(User, Client, Vec<Scope>, i64), Error> {
        let password = &request.password.as_ref().ok_or(Error::MissingPassword)?;
        let client = self.authenticate_client(&request).await?;
        let user = self
            .authenticator
            .authenticate_user(username, password)
            .await
            .map_err(|e| Error::WrongUsernameOrPassword(format!("{}", e)))?;

        let allowed_scopes = BTreeSet::from_iter(client.allowed_scopes.clone());
        let requested_scopes = match &request.scope {
            None => Default::default(),
            Some(scopes) => BTreeSet::from_iter(parse_scope_names(scopes)),
        };

        let scopes = allowed_scopes
            .intersection(&requested_scopes)
            .map(|v| self.scope_store.get(v))
            .map(Option::unwrap)
            .collect();

        Ok((user, client, scopes, Local::now().timestamp()))
    }

    async fn grant_with_refresh_token(
        &self,
        request: Request,
    ) -> Result<(Token, Vec<Scope>, bool), Error> {
        let raw_token = &request
            .refresh_token
            .as_ref()
            .ok_or(Error::MissingRefreshToken)?;

        let refresh_token = self
            .token_validator
            .validate::<RefreshToken>(raw_token)
            .ok_or(Error::InvalidRefreshToken)?;

        let client = self.authenticate_client(&request).await?;

        if client.client_id != refresh_token.access_token.authorized_party {
            warn!(
                different_client = refresh_token.access_token.authorized_party,
                "client tried to use refresh_token issued to different client"
            );
            return Err(Error::InvalidRefreshToken);
        }

        let mut token = refresh_token.access_token;
        self.token_creator.renew(&mut token);

        let granted_scopes = BTreeSet::from_iter(refresh_token.scopes);
        let requested_scopes = match &request.scope {
            #[allow(clippy::redundant_clone)]
            // false positive https://github.com/rust-lang/rust-clippy/issues/10940
            None => granted_scopes.clone(),
            Some(scopes) => BTreeSet::from_iter(parse_scope_names(scopes)),
        };

        let actual_scopes = granted_scopes
            .intersection(&requested_scopes)
            .map(|v| self.scope_store.get(v))
            .map(Option::unwrap)
            .collect();

        Ok((token, actual_scopes, true))
    }

    async fn authenticate_client(&self, request: &Request) -> Result<Client, Error> {
        if let (Some(assertion), Some(assertion_type)) =
            (&request.client_assertion, &request.client_assertion_type)
        {
            self.authenticate_client_by_jwt(assertion_type.clone(), assertion.clone())
                .await
        } else {
            self.authenticate_client_by_password(request).await
        }
    }

    async fn authenticate_client_by_password(&self, request: &Request) -> Result<Client, Error> {
        let (client_id, password) = Self::look_for_client_password(
            request.basic_authentication.as_ref(),
            request.client_id.as_ref(),
            request.client_secret.as_ref(),
        )?;

        let client = match self.client_store.get(&client_id).await {
            Err(e) => {
                debug!(%e, "client not found");
                return Err(Error::WrongClientIdOrPassword);
            }
            Ok(c) => c,
        };

        match &client.client_type {
            ClientType::Public => {
                debug!("tried to authenticate public client");
                Err(Error::InvalidAuthorizationHeader)
            }
            ClientType::Confidential {
                password: stored_password,
                ..
            } => {
                if self
                    .authenticator
                    .authenticate_client(&client, stored_password, &password)
                    .await
                    .map_err(|_| Error::AuthenticationFailed)?
                {
                    Ok(client)
                } else {
                    debug!("password for client was wrong");
                    Err(Error::WrongClientIdOrPassword)
                }
            }
        }
    }

    fn look_for_client_password(
        basic_authentication: Option<&(String, String)>,
        client_id: Option<&String>,
        client_secret: Option<&String>,
    ) -> Result<(String, String), Error> {
        match basic_authentication {
            Some(value) => Ok(value.clone()),
            None => {
                if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
                    Ok((client_id.clone(), client_secret.clone()))
                } else {
                    Err(Error::MissingAuthorizationHeader)
                }
            }
        }
    }

    async fn authenticate_client_by_jwt(
        &self,
        assertion_type: String,
        assertion: String,
    ) -> Result<Client, Error> {
        if assertion_type != CLIENT_ASSERTION_TYPE {
            return Err(Error::InvalidAuthenticationTokenType);
        }

        let unsafe_assertion = match self.decode_token_insecurely::<ClientAssertion>(&assertion) {
            Err(_) => {
                return Err(Error::InvalidAuthenticationToken(
                    oauth2::ProtocolError::InvalidRequest,
                ));
            }
            Ok(token) => token,
        };

        let client = match self
            .client_store
            .get(&unsafe_assertion.claims.subject)
            .await
        {
            Err(e) => {
                debug!(
                    %e,
                    "client not found",
                );
                return Err(Error::InvalidAuthenticationToken(
                    oauth2::ProtocolError::InvalidClient,
                ));
            }
            Ok(v) => v,
        };

        let key = match client.get_decoding_key(unsafe_assertion.header.alg) {
            None => {
                return Err(Error::InvalidAuthenticationToken(
                    oauth2::ProtocolError::InvalidClient,
                ));
            }
            Some(v) => v,
        };

        let mut validation = jsonwebtoken::Validation::new(unsafe_assertion.header.alg);
        validation.leeway = 5;
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_issuer(&[unsafe_assertion.claims.subject]);

        validation.set_audience(&[self.issuer_configuration.token()]);
        match jsonwebtoken::decode::<ClientAssertion>(&assertion, &key, &validation) {
            Err(e) => {
                debug!(%e, "failed to decode authentication token");
                Err(Error::InvalidAuthenticationToken(
                    oauth2::ProtocolError::InvalidRequest,
                ))
            }
            Ok(_) => Ok(client),
        }
    }

    fn decode_token_insecurely<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<TokenData<T>, ()> {
        let mut error = None;
        for algorithm in &[
            Algorithm::HS256,
            Algorithm::HS384,
            Algorithm::HS512,
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::EdDSA,
        ] {
            let mut validation = jsonwebtoken::Validation::new(*algorithm);
            validation.leeway = 5;
            validation.validate_exp = true;
            validation.validate_nbf = false;
            validation.insecure_disable_signature_validation();

            match jsonwebtoken::decode::<T>(token, &DecodingKey::from_secret(&[]), &validation) {
                Err(e) => {
                    error = Some(e);
                }
                Ok(v) => {
                    return Ok(v);
                }
            }
        }
        if let Some(e) = error {
            debug!(%e, "token invalid");
        }
        Err(())
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidAuthenticationToken(oauth2::ProtocolError),
    InvalidAuthenticationTokenType,
    InvalidAuthorizationHeader,
    MissingAuthorizationHeader,
    WrongClientIdOrPassword,
    MissingRefreshToken,
    InvalidRefreshToken,
    MissingUsername,
    MissingPassword,
    WrongUsernameOrPassword(String),
    MissingRedirectUri,
    MissingAuthorizationCode,
    MissingClientId,
    ConfidentialClientMustAuthenticate,
    InvalidAuthorizationCode,
    UnsupportedGrantType,
    TokenEncodingFailed,
    RefreshTokenEncodingFailed,
    AuthenticationFailed,
}

fn verify_pkce(challenge: CodeChallenge, verifier: Option<String>) -> Result<(), Error> {
    if let Some(verifier) = verifier {
        let verifier = match CodeVerifier::try_from(verifier.as_str()) {
            Err(e) => {
                debug!(%verifier, %e, "PKCE verifier invalid");
                return Err(Error::InvalidAuthorizationCode);
            }
            Ok(v) => v,
        };
        if !challenge.verify(verifier) {
            debug!("PKCE verifier doesn't match");
            Err(Error::InvalidAuthorizationCode)
        } else {
            Ok(())
        }
    } else {
        debug!("client requires PKCE but request contains none");
        Err(Error::InvalidAuthorizationCode)
    }
}

pub mod inject {
    use super::Handler;
    use crate::authenticator::Authenticator;
    use crate::issuer_configuration::IssuerConfiguration;
    use crate::store::{AuthorizationCodeStore, ClientStore, ScopeStore, UserStore};
    use crate::token::{TokenCreator, TokenValidator};
    use std::sync::Arc;

    #[allow(clippy::too_many_arguments)]
    pub fn handler(
        client_store: Arc<dyn ClientStore>,
        user_store: Arc<dyn UserStore>,
        auth_code_store: Arc<dyn AuthorizationCodeStore>,
        token_creator: TokenCreator,
        authenticator: Arc<Authenticator>,
        token_validator: Arc<TokenValidator>,
        scope_store: Arc<dyn ScopeStore>,
        issuer_configuration: IssuerConfiguration,
    ) -> Handler {
        Handler {
            client_store,
            user_store,
            auth_code_store,
            token_creator,
            authenticator,
            token_validator,
            scope_store,
            issuer_configuration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::test_fixtures::authenticator;
    use crate::store::test_fixtures::build_test_client_store;
    use crate::store::test_fixtures::build_test_scope_store;
    use crate::store::test_fixtures::build_test_user_store;
    use crate::store::test_fixtures::PUBLIC_CLIENT;
    use crate::store::test_fixtures::UNKNOWN_CLIENT_ID;
    use crate::store::test_fixtures::{build_test_auth_code_store, CONFIDENTIAL_CLIENT, USER};
    use crate::store::AuthorizationCodeRequest;
    use crate::test_fixtures::build_test_issuer_config;
    use crate::test_fixtures::build_test_token_creator;
    use crate::test_fixtures::build_test_token_validator;
    use test_log::test;

    #[test(tokio::test)]
    async fn missing_redirect_uri_is_rejected() {
        let request = Request::default();

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::MissingRedirectUri), response);
    }

    #[test(tokio::test)]
    async fn missing_code_is_rejected() {
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            redirect_uri: Some("fdsa".to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::MissingAuthorizationCode), response);
    }

    #[test(tokio::test)]
    async fn missing_client_id_is_rejected() {
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some("fdsa".to_string()),
            redirect_uri: Some("fdsa".to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::MissingClientId), response);
    }

    #[test(tokio::test)]
    async fn unknown_client_is_rejected() {
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some("fdsa".to_string()),
            redirect_uri: Some("fdsa".to_string()),
            client_id: Some(UNKNOWN_CLIENT_ID.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::WrongClientIdOrPassword), response);
    }

    #[test(tokio::test)]
    async fn unknown_auth_code_is_rejected() {
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some("fdsa".to_string()),
            redirect_uri: Some("fdsa".to_string()),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::InvalidAuthorizationCode), response);
    }

    #[test(tokio::test)]
    async fn wrong_redirect_uri_is_rejected() {
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: PUBLIC_CLIENT,
                user: USER,
                redirect_uri: &redirect_uri,
                scope: "",
                insertion_time: Local::now(),
                authentication_time: Local::now(),
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some(auth_code + "/wrong"),
            redirect_uri: Some(redirect_uri),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            ..Request::default()
        };

        let response = uut_with_auth_code_store(auth_code_store)
            .grant_tokens(request)
            .await;

        assert_eq!(Err(Error::InvalidAuthorizationCode), response);
    }

    #[test(tokio::test)]
    async fn expired_code_is_rejected() {
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let creation_time = Local::now() - Duration::minutes(2 * AUTH_CODE_LIFE_TIME);
        let auth_code = auth_code_store
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: PUBLIC_CLIENT,
                user: USER,
                redirect_uri: &redirect_uri,
                scope: "",
                insertion_time: creation_time,
                authentication_time: Local::now(),
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some(auth_code),
            redirect_uri: Some(redirect_uri),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            ..Request::default()
        };

        let response = uut_with_auth_code_store(auth_code_store)
            .grant_tokens(request)
            .await;

        assert_eq!(Err(Error::InvalidAuthorizationCode), response);
    }

    #[test(tokio::test)]
    async fn valid_token_is_issued() {
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: PUBLIC_CLIENT,
                user: USER,
                redirect_uri: &redirect_uri,
                scope: "",
                insertion_time: Local::now(),
                authentication_time: Local::now(),
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some(auth_code),
            redirect_uri: Some(redirect_uri),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            ..Request::default()
        };

        let response = uut_with_auth_code_store(auth_code_store)
            .grant_tokens(request)
            .await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(!response.0.is_empty());
        assert_eq!(None, response.1);
    }

    #[test(tokio::test)]
    async fn confidential_client_without_basic_auth_is_rejected() {
        let redirect_uri = "fdsa".to_string();
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some("fdsa".to_string()),
            redirect_uri: Some(redirect_uri),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::ConfidentialClientMustAuthenticate), response);
    }

    #[test(tokio::test)]
    async fn issue_valid_token_for_correct_password() {
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: CONFIDENTIAL_CLIENT,
                user: USER,
                redirect_uri: &redirect_uri,
                scope: "",
                insertion_time: Local::now(),
                authentication_time: Local::now(),
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;
        let request = Request {
            grant_type: GrantType::AuthorizationCode,
            code: Some(auth_code),
            redirect_uri: Some(redirect_uri),
            basic_authentication: Some((
                CONFIDENTIAL_CLIENT.to_string(),
                CONFIDENTIAL_CLIENT.to_string(),
            )),
            ..Request::default()
        };

        let response = uut_with_auth_code_store(auth_code_store)
            .grant_tokens(request)
            .await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(!response.0.is_empty());
        assert!(response.1.is_some());
    }

    #[test(tokio::test)]
    async fn public_client_cannot_get_access_token_for_itself() {
        let request = Request {
            grant_type: GrantType::ClientCredentials,
            basic_authentication: Some((PUBLIC_CLIENT.to_string(), PUBLIC_CLIENT.to_string())),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::InvalidAuthorizationHeader), response);
    }

    #[test(tokio::test)]
    async fn confidential_client_gets_access_token_for_itself() {
        let request = Request {
            grant_type: GrantType::ClientCredentials,
            basic_authentication: Some((
                CONFIDENTIAL_CLIENT.to_string(),
                CONFIDENTIAL_CLIENT.to_string(),
            )),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(!response.0.is_empty());
        assert!(response.1.is_some());
    }

    #[test(tokio::test)]
    async fn missing_username_is_rejected_with_password_grant() {
        let request = Request {
            grant_type: GrantType::Password,
            basic_authentication: Some((
                CONFIDENTIAL_CLIENT.to_string(),
                CONFIDENTIAL_CLIENT.to_string(),
            )),
            password: Some(USER.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::MissingUsername), response);
    }

    #[test(tokio::test)]
    async fn missing_password_is_rejected_with_password_grant() {
        let request = Request {
            grant_type: GrantType::Password,
            basic_authentication: Some((
                CONFIDENTIAL_CLIENT.to_string(),
                CONFIDENTIAL_CLIENT.to_string(),
            )),
            username: Some(USER.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::MissingPassword), response);
    }

    #[test(tokio::test)]
    async fn public_client_cannot_use_password_grant() {
        let request = Request {
            grant_type: GrantType::Password,
            basic_authentication: Some((PUBLIC_CLIENT.to_string(), PUBLIC_CLIENT.to_string())),
            username: Some(USER.to_string()),
            password: Some(USER.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::InvalidAuthorizationHeader), response);
    }

    #[test(tokio::test)]
    async fn confidential_client_can_use_password_grant() {
        let request = Request {
            grant_type: GrantType::Password,
            basic_authentication: Some((
                CONFIDENTIAL_CLIENT.to_string(),
                CONFIDENTIAL_CLIENT.to_string(),
            )),
            username: Some(USER.to_string()),
            password: Some(USER.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(!response.0.is_empty());
        assert!(response.1.is_some());
    }

    #[test(tokio::test)]
    async fn missing_refresh_token_is_rejected() {
        let request = Request {
            grant_type: GrantType::RefreshToken,
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::MissingRefreshToken), response);
    }

    #[test(tokio::test)]
    async fn invalid_refresh_token_is_rejected() {
        let request = Request {
            grant_type: GrantType::RefreshToken,
            refresh_token: Some("invalid".to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::InvalidRefreshToken), response);
    }

    #[test(tokio::test)]
    async fn invalid_client_credentials_with_refresh_token_are_rejected() {
        let request = Request {
            grant_type: GrantType::RefreshToken,
            basic_authentication: Some((CONFIDENTIAL_CLIENT.to_string(), "wrong".to_string())),
            refresh_token: Some(build_refresh_token(CONFIDENTIAL_CLIENT).await),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::WrongClientIdOrPassword), response);
    }

    #[test(tokio::test)]
    async fn refresh_token_from_different_client_is_rejected() {
        let request = Request {
            grant_type: GrantType::RefreshToken,
            basic_authentication: Some((
                CONFIDENTIAL_CLIENT.to_string(),
                CONFIDENTIAL_CLIENT.to_string(),
            )),
            refresh_token: Some(build_refresh_token(PUBLIC_CLIENT).await),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert_eq!(Err(Error::InvalidRefreshToken), response);
    }

    #[test(tokio::test)]
    async fn successful_refresh_token_authentication() {
        let request = Request {
            grant_type: GrantType::RefreshToken,
            basic_authentication: Some((
                CONFIDENTIAL_CLIENT.to_string(),
                CONFIDENTIAL_CLIENT.to_string(),
            )),
            refresh_token: Some(build_refresh_token(CONFIDENTIAL_CLIENT).await),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(!response.0.is_empty());
        assert!(response.1.is_some());
    }

    #[test(tokio::test)]
    async fn successful_authentication_with_secret_as_post_parameter() {
        let request = Request {
            grant_type: GrantType::RefreshToken,
            refresh_token: Some(build_refresh_token(CONFIDENTIAL_CLIENT).await),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            client_secret: Some(CONFIDENTIAL_CLIENT.to_string()),
            ..Request::default()
        };

        let response = uut().grant_tokens(request).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(!response.0.is_empty());
        assert!(response.1.is_some());
    }

    fn uut() -> Handler {
        uut_with_auth_code_store(build_test_auth_code_store())
    }

    fn uut_with_auth_code_store(auth_code_store: Arc<dyn AuthorizationCodeStore>) -> Handler {
        Handler {
            client_store: build_test_client_store(),
            user_store: build_test_user_store(),
            auth_code_store: auth_code_store.clone(),
            token_creator: build_test_token_creator(),
            authenticator: Arc::new(authenticator()),
            token_validator: Arc::new(build_test_token_validator()),
            scope_store: build_test_scope_store(),
            issuer_configuration: build_test_issuer_config(),
        }
    }

    async fn build_refresh_token(client_id: &str) -> String {
        let token_creator = build_test_token_creator();
        let token = token_creator.build_token(
            &build_test_user_store().get(USER).await.unwrap(),
            &build_test_client_store().get(client_id).await.unwrap(),
            &Vec::new(),
            0,
        );
        token_creator
            .finalize_refresh_token(token_creator.build_refresh_token(token, &Vec::new()))
            .unwrap()
    }
}
