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

#![expect(clippy::unwrap_used, reason = "this is test code")]

use std::sync::RwLock;
use test_log::test;
use tiny_auth_business::authorize_endpoint::inject::handler;
use tiny_auth_business::authorize_endpoint::{AuthorizeRequestState, Error, Request, Session};
use tiny_auth_business::data::client::Client;
use tiny_auth_business::oauth2::ResponseType::Code;
use tiny_auth_business::oidc::ResponseType;
use tiny_auth_test_fixtures::data::client::CONFIDENTIAL_CLIENT;
use tiny_auth_test_fixtures::store::client_store::build_test_client_store;

#[test(tokio::test)]
async fn forbidden_scope_is_pruned() {
    let uut = handler(build_test_client_store());

    let session = MockSession::new();
    let actual = uut
        .handle(
            Request {
                scope: format!(
                    "{} {}",
                    CONFIDENTIAL_CLIENT.allowed_scopes.first().unwrap(),
                    "forbidden"
                )
                .into(),
                ..request_for(&CONFIDENTIAL_CLIENT)
            },
            &session,
        )
        .await;

    assert_eq!(Ok(()), actual);
    let expected = vec![CONFIDENTIAL_CLIENT
        .allowed_scopes
        .first()
        .unwrap()
        .to_owned()];
    let actual = <Option<AuthorizeRequestState> as Clone>::clone(&session.0.write().unwrap())
        .unwrap()
        .scopes;
    assert_eq!(expected, actual);
}

struct MockSession(RwLock<Option<AuthorizeRequestState>>);

impl MockSession {
    pub fn new() -> Self {
        Self(RwLock::new(None))
    }
}

impl Session for &MockSession {
    fn store(&self, state: AuthorizeRequestState) -> Result<(), Error> {
        let mut guard = self.0.write().unwrap();
        *guard = Some(state);
        Ok(())
    }
}

fn request_for(client: &Client) -> Request {
    Request {
        client_id: Some(client.client_id.clone()),
        scope: client.allowed_scopes.first().unwrap().to_owned().into(),
        redirect_uri: client.redirect_uris.first().unwrap().clone().into(),
        response_type: Some(format!("{}", ResponseType::OAuth2(Code))),
        ..Default::default()
    }
}
