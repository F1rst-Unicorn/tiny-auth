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

use test_log::test;
use tiny_auth_business::authenticator::Authenticator;
use tiny_auth_business::data::password::Password;
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::store::{PasswordStore, UserStore};
use tiny_auth_test_fixtures::authenticator::authenticator;
use tiny_auth_test_fixtures::data::client::CONFIDENTIAL_CLIENT;
use tiny_auth_test_fixtures::data::password::in_place_password_store;
use tiny_auth_test_fixtures::store::client_store::build_test_client_store;
use tiny_auth_test_fixtures::store::user_store::{build_test_user_store, USER};

#[test(tokio::test)]
async fn own_constructed_password_is_verifiable() {
    let uut = authenticator();
    let user = build_test_user_store().get(USER).await.unwrap();
    let new_password = "new-password";

    let actual = uut
        .construct_password(user.clone(), new_password)
        .await
        .unwrap();

    assert!(in_place_password_store()
        .verify(user.name.as_str(), &actual, new_password)
        .await
        .unwrap_or(false));
}

#[test(tokio::test)]
async fn successful_client_authentication_works() {
    let uut = authenticator();
    let client = build_test_client_store()
        .get(&CONFIDENTIAL_CLIENT.client_id)
        .await
        .unwrap();
    let password_to_check = client.client_id.to_owned();

    let actual = uut
        .authenticate_client(
            &client,
            &Password::Plain(password_to_check.clone()),
            &password_to_check,
        )
        .await
        .unwrap();

    assert!(actual);
}

#[test(tokio::test)]
async fn failing_client_authentication_works() {
    let uut = authenticator();
    let client = build_test_client_store()
        .get(&CONFIDENTIAL_CLIENT.client_id)
        .await
        .unwrap();
    let actual_password = Password::Plain(client.client_id.to_owned());
    let password_to_check = "different";

    let actual = uut
        .authenticate_client(&client, &actual_password, password_to_check)
        .await
        .unwrap();

    assert!(!actual);
}
