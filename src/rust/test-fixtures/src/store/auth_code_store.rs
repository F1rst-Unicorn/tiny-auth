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
use async_trait::async_trait;
use chrono::{DateTime, Duration, Local};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tiny_auth_business::pkce::CodeChallenge;
use tiny_auth_business::store::AuthCodeValidationError::NotFound;
use tiny_auth_business::store::{
    AuthCodeError, AuthCodeValidationError, AuthorizationCodeRequest, AuthorizationCodeResponse,
    AuthorizationCodeStore, ValidationRequest,
};
use url::Url;

type AuthCodeStoreKey = (String, String);
type AuthCodeStoreValue = (
    Url,
    String,
    String,
    DateTime<Local>,
    DateTime<Local>,
    Option<String>,
    Option<CodeChallenge>,
);

struct TestAuthorizationCodeStore {
    store: RefCell<HashMap<AuthCodeStoreKey, AuthCodeStoreValue>>,
}

unsafe impl Sync for TestAuthorizationCodeStore {}
unsafe impl Send for TestAuthorizationCodeStore {}

#[async_trait]
impl AuthorizationCodeStore for TestAuthorizationCodeStore {
    async fn get_authorization_code<'a>(
        &self,
        request: AuthorizationCodeRequest<'a>,
    ) -> Result<String, AuthCodeError> {
        self.store.borrow_mut().insert(
            (
                request.client_id.to_owned(),
                request.insertion_time.to_rfc3339(),
            ),
            (
                request.redirect_uri.to_owned(),
                request.user.to_owned(),
                request.scope.to_owned(),
                request.insertion_time,
                request.authentication_time,
                request.nonce,
                request.pkce_challenge,
            ),
        );
        Ok(request.insertion_time.to_rfc3339())
    }

    async fn validate<'a>(
        &self,
        request: ValidationRequest<'a>,
    ) -> Result<AuthorizationCodeResponse, AuthCodeValidationError> {
        let (redirect_uri, user, scope, insertion_time, authentication_time, nonce, pkce_challenge) =
            self.store
                .borrow_mut()
                .remove(&(
                    request.client_id.to_owned(),
                    request.authorization_code.to_owned(),
                ))
                .ok_or(NotFound)?;
        Ok(AuthorizationCodeResponse {
            redirect_uri,
            stored_duration: request
                .validation_time
                .signed_duration_since(insertion_time),
            username: user,
            scopes: scope,
            authentication_time,
            nonce,
            pkce_challenge,
        })
    }

    async fn clear_expired_codes(&self, _: DateTime<Local>, _: Duration) {}
}

pub fn build_test_auth_code_store() -> Arc<impl AuthorizationCodeStore> {
    Arc::new(TestAuthorizationCodeStore {
        store: RefCell::new(HashMap::new()),
    })
}
