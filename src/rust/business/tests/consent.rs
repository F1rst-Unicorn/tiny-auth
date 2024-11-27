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

use std::sync::Arc;
use test_log::test;
use tiny_auth_business::consent::{inject, Handler};
use tiny_auth_business::data::client::Client;
use tiny_auth_business::data::user::User;
use tiny_auth_test_fixtures::data::client::ClientExt;
use tiny_auth_test_fixtures::data::client::DEFAULT_CLIENT;
use tiny_auth_test_fixtures::data::user::UserExt;
use tiny_auth_test_fixtures::data::user::DEFAULT_USER;
use tiny_auth_test_fixtures::store::auth_code_store::build_test_auth_code_store;
use tiny_auth_test_fixtures::store::client_store::TestClientStore;
use tiny_auth_test_fixtures::store::scope_store::build_test_scope_store;
use tiny_auth_test_fixtures::store::user_store::TestUserStore;
use tiny_auth_test_fixtures::token::build_test_token_creator;

#[test(tokio::test)]
async fn can_skip_consent_if_all_scopes_allowed() {
    let scope = "email";
    let client = DEFAULT_CLIENT.clone().with_allowed_scopes([scope]);
    let user = DEFAULT_USER
        .clone()
        .with_allowed_scopes([(client.client_id.as_str(), [scope])]);
    let uut = custom_handler([user.clone()], [client.clone()]);

    let actual = uut
        .can_skip_consent_screen(
            user.name.as_str(),
            client.client_id.as_str(),
            &[String::from(scope)],
        )
        .await;

    assert!(actual.is_ok());
    assert!(actual.unwrap());
}

#[test(tokio::test)]
async fn must_consent_if_scope_is_not_allowed() {
    let scope = "email";
    let client = DEFAULT_CLIENT.clone().with_allowed_scopes([scope]);
    let user = DEFAULT_USER
        .clone()
        .with_allowed_scopes([(&client.client_id, ["openid"])]);
    let uut = custom_handler([user.clone()], [client.clone()]);

    let actual = uut
        .can_skip_consent_screen(
            user.name.as_str(),
            client.client_id.as_str(),
            &[String::from(scope)],
        )
        .await;

    assert!(actual.is_ok());
    assert!(!actual.unwrap());
}

fn custom_handler(
    users: impl IntoIterator<Item = User>,
    clients: impl IntoIterator<Item = Client>,
) -> Handler {
    inject::handler(
        build_test_scope_store(),
        Arc::new(users.into_iter().collect::<TestUserStore>()),
        Arc::new(clients.into_iter().collect::<TestClientStore>()),
        build_test_auth_code_store(),
        build_test_token_creator(),
    )
}
