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

use crate::oauth2;
use crate::oidc;
use crate::pkce::CodeChallenge;
use crate::scope::Scope;
use crate::store::AuthorizationCodeStore;
use crate::store::ClientStore;
use crate::store::ScopeStore;
use crate::store::UserStore;
use crate::store::{AuthCodeError, AuthorizationCodeRequest};
use crate::token::{
    Access, EncodedAccessToken, EncodedIdToken, EncodedRefreshToken, Id, TokenCreator,
};
use chrono::{DateTime, Duration, Local};
use std::collections::BTreeSet;
use std::sync::Arc;
use tracing::{debug, instrument, warn, Level};
use url::Url;

pub struct Request<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a Url,
    pub authenticated_username: &'a str,
    pub requested_scopes: &'a [String],
    pub user_confirmed_scopes: &'a BTreeSet<String>,
    pub response_types: &'a [oidc::ResponseType],
    pub auth_time: DateTime<Local>,
    pub nonce: Option<&'a String>,
    pub code_challenge: Option<&'a CodeChallenge>,
}

pub struct Response {
    pub access_token: Option<EncodedAccessToken>,
    pub id_token: Option<EncodedIdToken>,
    pub refresh_token: Option<EncodedRefreshToken>,
    pub code: Option<String>,
    pub expiration: Option<Duration>,
}

pub enum Error {
    UserNotFound,
    ClientNotFound,
    AuthCodeNotGenerated,
    ScopesNotFound,
    TokenEncodingError,
}

pub struct UserNotFound;

#[derive(Clone)]
pub struct Handler {
    scope_store: Arc<dyn ScopeStore>,
    user_store: Arc<dyn UserStore>,
    client_store: Arc<dyn ClientStore>,
    auth_code_store: Arc<dyn AuthorizationCodeStore>,
    token_creator: TokenCreator,
}

impl Handler {
    #[instrument(level = Level::DEBUG, skip_all, fields(
        client = client_id))]
    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(user = authenticated_username))]
    pub async fn can_skip_consent_screen(
        &self,
        authenticated_username: &str,
        client_id: &str,
        requested_scopes: &[String],
    ) -> Result<bool, UserNotFound> {
        let user = match self.user_store.get(authenticated_username).await {
            Err(e) => {
                debug!(%e, "authenticated user not found");
                return Err(UserNotFound);
            }
            Ok(v) => v,
        };

        let allowed_scopes = user.get_allowed_scopes(client_id);
        let requested_scopes = BTreeSet::from_iter(requested_scopes);
        return Ok(requested_scopes.is_subset(&allowed_scopes.iter().collect()));
    }

    pub async fn get_scope(&self, key: &str) -> Option<Scope> {
        self.scope_store.get(key).await.ok()
    }

    #[instrument(level = Level::DEBUG, skip_all, fields(
        client = request.client_id,
        requested_scopes = ?request.requested_scopes,
        user_confirmed_scopes = request.user_confirmed_scopes
            .iter()
            .fold(String::new(), |a, b| a + " " + b),
        response_types = ?request.response_types,
        pkce = request.code_challenge.is_some()))]
    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(user = request.authenticated_username))]
    pub async fn issue_token<'a>(&self, request: Request<'a>) -> Result<Response, Error> {
        let requested_scopes = BTreeSet::from_iter(request.requested_scopes);
        let scopes = request
            .user_confirmed_scopes
            .intersection(&requested_scopes.into_iter().cloned().collect())
            .map(Clone::clone)
            .collect::<Vec<String>>();

        let mut response = Response {
            access_token: None,
            id_token: None,
            refresh_token: None,
            code: None,
            expiration: None,
        };
        if let Err(e) = self
            .generate_authz_code(&request, &scopes, &mut response)
            .await
        {
            warn!(%e, "failed to generate auth code");
            return Err(Error::AuthCodeNotGenerated);
        };

        if request
            .response_types
            .contains(&oidc::ResponseType::Oidc(oidc::OidcResponseType::IdToken))
            || request
                .response_types
                .contains(&oidc::ResponseType::OAuth2(oauth2::ResponseType::Token))
        {
            let user = match self.user_store.get(request.authenticated_username).await {
                Err(e) => {
                    debug!(%e, "user not found");
                    return Err(Error::UserNotFound);
                }
                Ok(user) => user,
            };

            let client = match self.client_store.get(request.client_id).await {
                Err(e) => {
                    debug!(%e, "client not found");
                    return Err(Error::ClientNotFound);
                }
                Ok(client) => client,
            };

            let all_scopes = match self.scope_store.get_all(&scopes).await {
                Err(e) => {
                    warn!(%e, "failed to load scopes");
                    return Err(Error::ScopesNotFound);
                }
                Ok(v) => v,
            };

            if request
                .response_types
                .contains(&oidc::ResponseType::Oidc(oidc::OidcResponseType::IdToken))
            {
                let mut token = self.token_creator.build_token::<Id>(
                    &user,
                    &client,
                    &all_scopes,
                    request.auth_time.timestamp(),
                );
                token.set_nonce(request.nonce.cloned());
                let encoded_token = match self.token_creator.finalize_id_token(token.clone()) {
                    Err(e) => {
                        debug!(%e, "failed to encode token");
                        return Err(Error::TokenEncodingError);
                    }
                    Ok(token) => token,
                };
                response.id_token = Some(encoded_token);
            }
            if request
                .response_types
                .contains(&oidc::ResponseType::OAuth2(oauth2::ResponseType::Token))
            {
                let mut token = self.token_creator.build_token::<Access>(
                    &user,
                    &client,
                    &all_scopes,
                    request.auth_time.timestamp(),
                );
                token.set_nonce(request.nonce.cloned());
                let encoded_token = match self.token_creator.finalize_access_token(token.clone()) {
                    Err(e) => {
                        debug!(%e, "failed to encode token");
                        return Err(Error::TokenEncodingError);
                    }
                    Ok(token) => token,
                };
                response.access_token = Some(encoded_token);
            }
            if let oauth2::ClientType::Confidential { .. } = client.client_type {
                let encoded_refresh_token = match self.token_creator.finalize_refresh_token(
                    self.token_creator.build_fresh_refresh_token(
                        &all_scopes,
                        &user.name,
                        &client.client_id,
                        request.auth_time.timestamp(),
                    ),
                ) {
                    Err(e) => {
                        debug!(%e, "failed to encode refresh token");
                        return Err(Error::TokenEncodingError);
                    }
                    Ok(token) => token,
                };
                response.refresh_token = Some(encoded_refresh_token);
            }

            response.expiration = Some(self.token_creator.expiration());
        }

        Ok(response)
    }

    async fn generate_authz_code(
        &self,
        request: &Request<'_>,
        scopes: &[String],
        response: &mut Response,
    ) -> Result<(), AuthCodeError> {
        if request
            .response_types
            .contains(&oidc::ResponseType::OAuth2(oauth2::ResponseType::Code))
        {
            let code = self
                .auth_code_store
                .get_authorization_code(AuthorizationCodeRequest {
                    client_id: request.client_id,
                    user: request.authenticated_username,
                    redirect_uri: request.redirect_uri,
                    scope: &scopes.join(" "),
                    insertion_time: Local::now(),
                    authentication_time: request.auth_time,
                    nonce: request.nonce.cloned(),
                    pkce_challenge: request.code_challenge.cloned(),
                })
                .await?;
            response.code = Some(code);
        }
        Ok(())
    }
}

pub mod inject {
    use super::*;

    pub fn handler(
        scope_store: Arc<dyn ScopeStore>,
        user_store: Arc<dyn UserStore>,
        client_store: Arc<dyn ClientStore>,
        auth_code_store: Arc<dyn AuthorizationCodeStore>,
        token_creator: TokenCreator,
    ) -> Handler {
        Handler {
            scope_store,
            user_store,
            client_store,
            auth_code_store,
            token_creator,
        }
    }
}

pub mod test_fixtures {
    use super::*;
    use crate::store::test_fixtures::*;
    use crate::test_fixtures::build_test_token_creator;

    pub fn handler() -> Handler {
        inject::handler(
            build_test_scope_store(),
            build_test_user_store(),
            build_test_client_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
    }
}
