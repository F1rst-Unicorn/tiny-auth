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
use crate::clock::Clock;
use crate::data::client::Client;
use crate::data::client::ClientType;
use crate::data::scope::parse_scope_names;
use crate::data::scope::Scope;
use crate::data::user::User;
use crate::issuer_configuration::IssuerConfiguration;
use crate::oauth2;
use crate::oauth2::GrantType;
use crate::pkce::{CodeChallenge, CodeVerifier};
use crate::store::ScopeStore;
use crate::store::UserStore;
use crate::store::AUTH_CODE_LIFE_TIME;
use crate::store::{AuthCodeValidationError, ClientStore};
use crate::store::{AuthorizationCodeStore, ValidationRequest};
use crate::token::TokenValidator;
use crate::token::{
    Access, EncodedAccessToken, EncodedIdToken, EncodedRefreshToken, Id, RefreshToken,
};
use crate::token::{Token, TokenCreator};
use async_trait::async_trait;
use chrono::Duration;
use futures_util::future::join_all;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use serde_derive::Deserialize;
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::iter::FromIterator;
use std::sync::Arc;
use tracing::{debug, instrument, Level, Span};
use tracing::{info, warn};
use url::Url;

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// [OAuth JWT Assertions](https://www.rfc-editor.org/rfc/rfc7523.txt)
#[derive(Deserialize)]
struct ClientAssertion {
    #[serde(rename = "iss")]
    #[expect(dead_code)] // read by crate jsonwebtoken
    issuer: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "aud")]
    #[expect(dead_code)] // read by crate jsonwebtoken
    audience: String,

    #[serde(rename = "jti")]
    #[expect(dead_code)]
    id: String,

    #[serde(rename = "exp")]
    #[expect(dead_code)] // read by crate jsonwebtoken
    expiration_time: i64,

    #[serde(rename = "iat")]
    #[expect(dead_code)]
    issuance_time: i64,
}

#[derive(Default)]
pub struct Request {
    pub basic_authentication: Option<(String, String)>,
    pub grant_type: GrantType,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<Url>,
    pub scope: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub refresh_token: Option<EncodedRefreshToken>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
    pub pkce_verifier: Option<String>,
}

type AuthorizationCodeResult = (User, Client, Vec<Scope>, i64, Option<String>);

#[async_trait]
pub trait Handler: Send + Sync {
    async fn grant_tokens(
        &self,
        request: Request,
    ) -> Result<
        (
            EncodedAccessToken,
            EncodedIdToken,
            Option<EncodedRefreshToken>,
            Vec<Scope>,
        ),
        Error,
    >;
}

#[derive(Clone)]
pub struct HandlerImpl<Authenticator, Clock, TokenCreator> {
    client_store: Arc<dyn ClientStore>,
    user_store: Arc<dyn UserStore>,
    auth_code_store: Arc<dyn AuthorizationCodeStore>,
    token_creator: TokenCreator,
    authenticator: Arc<Authenticator>,
    token_validator: Arc<TokenValidator>,
    scope_store: Arc<dyn ScopeStore>,
    issuer_configuration: IssuerConfiguration,
    clock: Clock,
}

#[async_trait]
impl<A: Authenticator, C: Clock, T: TokenCreator> Handler for HandlerImpl<A, C, T> {
    #[instrument(level = Level::DEBUG, skip_all, fields(
        client = request.client_id,
        pkce = request.pkce_verifier.is_some(),
        nonce,
        code = request.code,
        grant_type = ?request.grant_type))]
    async fn grant_tokens(
        &self,
        request: Request,
    ) -> Result<
        (
            EncodedAccessToken,
            EncodedIdToken,
            Option<EncodedRefreshToken>,
            Vec<Scope>,
        ),
        Error,
    > {
        let span = Span::current();
        let (access_token, id_token, refresh_token, scopes) =
            self.grant_token(request, span).await?;

        let encoded_access_token = match self.token_creator.finalize_access_token(access_token) {
            Err(e) => {
                debug!(%e, "failed to encode token");
                return Err(Error::TokenEncodingFailed);
            }
            Ok(token) => token,
        };
        let encoded_id_token = match self.token_creator.finalize_id_token(id_token) {
            Err(e) => {
                debug!(%e, "failed to encode token");
                return Err(Error::TokenEncodingFailed);
            }
            Ok(token) => token,
        };
        let refresh_token = refresh_token
            .map(|v| match self.token_creator.finalize_refresh_token(v) {
                Err(e) => {
                    debug!(%e, "failed to encode token");
                    Err(Error::TokenEncodingFailed)
                }
                Ok(v) => Ok(v),
            })
            .transpose()?;

        Ok((
            encoded_access_token,
            encoded_id_token,
            refresh_token,
            scopes,
        ))
    }
}

impl<A: Authenticator, C: Clock, T: TokenCreator> HandlerImpl<A, C, T> {
    #[expect(clippy::type_complexity)] // debatable
    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(user))]
    async fn grant_token(
        &self,
        request: Request,
        span: Span,
    ) -> Result<(Token<Access>, Token<Id>, Option<RefreshToken>, Vec<Scope>), Error> {
        let cid_span = Span::current();
        match request.grant_type {
            GrantType::RefreshToken => self.grant_with_refresh_token(request, span, cid_span).await,
            _ => {
                let (user, client, scopes, auth_time, nonce) = match request.grant_type {
                    GrantType::AuthorizationCode => {
                        self.grant_with_authorization_code(request, span, cid_span)
                            .await?
                    }
                    GrantType::ClientCredentials => self
                        .grant_with_client_credentials(request, cid_span)
                        .await
                        .map(|(a, b, c, d)| (a, b, c, d, None))?,
                    GrantType::Password => self
                        .grant_with_password(request, cid_span)
                        .await
                        .map(|(a, b, c, d)| (a, b, c, d, None))?,
                    _ => {
                        return Err(Error::UnsupportedGrantType);
                    }
                };

                let mut refresh_token = if let ClientType::Confidential { .. } = client.client_type
                {
                    Some(self.token_creator.build_fresh_refresh_token(
                        &scopes,
                        &user.name,
                        &client.client_id,
                        auth_time,
                    ))
                } else {
                    None
                };
                let mut access_token = self
                    .token_creator
                    .build_token::<Access>(&user, &client, &scopes, auth_time);
                let mut id_token = self
                    .token_creator
                    .build_token::<Id>(&user, &client, &scopes, auth_time);

                access_token.set_nonce(nonce.clone());
                if let Some(v) = refresh_token.as_mut() {
                    v.set_nonce(nonce.clone())
                }
                id_token.set_nonce(nonce);

                Ok((access_token, id_token, refresh_token, scopes))
            }
        }
    }

    async fn grant_with_authorization_code(
        &self,
        request: Request,
        span: Span,
        cid_span: Span,
    ) -> Result<AuthorizationCodeResult, Error> {
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

        let record = match self
            .auth_code_store
            .validate(ValidationRequest {
                client_id: &client.client_id,
                authorization_code: code,
                validation_time: self.clock.now(),
            })
            .await
        {
            Err(AuthCodeValidationError::NotFound) => {
                debug!(%code, "No authorization code found");
                return Err(Error::InvalidAuthorizationCode);
            }
            Err(e) => {
                info!(%e, "failed to validate auth code");
                return Err(Error::AuthenticationFailed);
            }
            Ok(v) => v,
        };
        cid_span.record("user", &record.username);
        span.record("nonce", &record.nonce);

        let redirect_uri_from_request = request
            .redirect_uri
            .as_ref()
            .ok_or(Error::MissingRedirectUri)?;
        if &record.redirect_uri != redirect_uri_from_request {
            debug!(
                expected = %record.redirect_uri,
                actual = %redirect_uri_from_request,
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
                crate::store::user_store::Error::NotFound => {
                    debug!("user not found");
                    Error::WrongUsernameOrPassword(format!("{}", WrongCredentials))
                }
                crate::store::user_store::Error::BackendError
                | crate::store::user_store::Error::BackendErrorWithContext(_) => {
                    Error::AuthenticationFailed
                }
            })?;

        let scopes = self
            .scope_store
            .get_all(&parse_scope_names(&record.scopes))
            .await
            .map_err(|_| Error::AuthenticationFailed)?;

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
        cid_span: Span,
    ) -> Result<(User, Client, Vec<Scope>, i64), Error> {
        let client = self.authenticate_client(&request).await?;
        cid_span.record("user", &client.client_id);
        let allowed_scopes = BTreeSet::from_iter(client.allowed_scopes.clone());
        let requested_scopes = match &request.scope {
            None => Default::default(),
            Some(scopes) => BTreeSet::from_iter(parse_scope_names(scopes)),
        };

        let scopes = join_all(
            allowed_scopes
                .intersection(&requested_scopes)
                .map(|v| self.scope_store.get(v)),
        )
        .await
        .into_iter()
        .flatten()
        .collect();

        Ok((
            client
                .clone()
                .try_into()
                .map_err(|_| Error::UnsupportedGrantType)?,
            client,
            scopes,
            self.clock.now().timestamp(),
        ))
    }

    async fn grant_with_password(
        &self,
        request: Request,
        cid_span: Span,
    ) -> Result<(User, Client, Vec<Scope>, i64), Error> {
        let username = &request.username.as_ref().ok_or(Error::MissingUsername)?;
        cid_span.record("user", username);
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

        let scopes = join_all(
            allowed_scopes
                .intersection(&requested_scopes)
                .map(|v| self.scope_store.get(v)),
        )
        .await
        .into_iter()
        .flatten()
        .collect();

        Ok((user, client, scopes, self.clock.now().timestamp()))
    }

    async fn grant_with_refresh_token(
        &self,
        request: Request,
        span: Span,
        cid_span: Span,
    ) -> Result<(Token<Access>, Token<Id>, Option<RefreshToken>, Vec<Scope>), Error> {
        let raw_token = request
            .refresh_token
            .as_ref()
            .ok_or(Error::MissingRefreshToken)?;

        let refresh_token = self
            .token_validator
            .validate::<RefreshToken>(raw_token.as_ref())
            .ok_or(Error::InvalidRefreshToken)?;
        cid_span.record("user", &refresh_token.subject);
        span.record("nonce", &refresh_token.nonce);
        let client = self.authenticate_client(&request).await?;

        if client.client_id != refresh_token.authorized_party {
            warn!(
                different_client = refresh_token.authorized_party,
                "client tried to use refresh_token issued to different client"
            );
            return Err(Error::InvalidRefreshToken);
        }

        let user = self
            .user_store
            .get(&refresh_token.subject)
            .await
            .map_err(|e| match e {
                crate::store::user_store::Error::NotFound => {
                    debug!("user not found");
                    Error::WrongUsernameOrPassword(format!("{}", WrongCredentials))
                }
                crate::store::user_store::Error::BackendError
                | crate::store::user_store::Error::BackendErrorWithContext(_) => {
                    Error::AuthenticationFailed
                }
            })?;

        let granted_scopes = BTreeSet::from_iter(refresh_token.scopes);
        let requested_scopes = match &request.scope {
            None => granted_scopes.clone(),
            Some(scopes) => BTreeSet::from_iter(parse_scope_names(scopes)),
        };

        let actual_scopes: Vec<_> = join_all(
            granted_scopes
                .intersection(&requested_scopes)
                .map(|v| self.scope_store.get(v)),
        )
        .await
        .into_iter()
        .flatten()
        .collect();

        let nonce = Some(refresh_token.nonce);
        let mut access_token = self.token_creator.build_token::<Access>(
            &user,
            &client,
            actual_scopes.as_slice(),
            refresh_token.auth_time,
        );
        let mut id_token = self.token_creator.build_token::<Id>(
            &user,
            &client,
            actual_scopes.as_slice(),
            refresh_token.auth_time,
        );
        let mut refresh_token = self.token_creator.build_fresh_refresh_token(
            &actual_scopes,
            &user.name,
            &client.client_id,
            refresh_token.auth_time,
        );
        access_token.set_nonce(nonce.clone());
        refresh_token.set_nonce(nonce.clone());
        id_token.set_nonce(nonce);

        Ok((access_token, id_token, Some(refresh_token), actual_scopes))
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
            Err(()) => {
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

    fn decode_token_insecurely<Token: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<TokenData<Token>, ()> {
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

            match jsonwebtoken::decode::<Token>(token, &DecodingKey::from_secret(&[]), &validation)
            {
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
    use super::{Handler, HandlerImpl};
    use crate::authenticator::Authenticator;
    use crate::clock::Clock;
    use crate::issuer_configuration::IssuerConfiguration;
    use crate::store::{AuthorizationCodeStore, ClientStore, ScopeStore, UserStore};
    use crate::token::{TokenCreator, TokenValidator};
    use std::sync::Arc;

    #[expect(clippy::too_many_arguments)]
    pub fn handler<A, C, T>(
        client_store: Arc<dyn ClientStore>,
        user_store: Arc<dyn UserStore>,
        auth_code_store: Arc<dyn AuthorizationCodeStore>,
        token_creator: T,
        authenticator: Arc<A>,
        token_validator: Arc<TokenValidator>,
        scope_store: Arc<dyn ScopeStore>,
        issuer_configuration: IssuerConfiguration,
        clock: C,
    ) -> impl Handler + 'static
    where
        A: Authenticator + 'static,
        T: TokenCreator + 'static,
        C: Clock + 'static,
    {
        HandlerImpl {
            client_store,
            user_store,
            auth_code_store,
            token_creator,
            authenticator,
            token_validator,
            scope_store,
            issuer_configuration,
            clock,
        }
    }
}
