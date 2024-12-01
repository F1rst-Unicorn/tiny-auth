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
use tiny_auth_business::authenticator::Error::PasswordStoreError;
use tiny_auth_business::authenticator::{inject, Authenticator};
use tiny_auth_business::data::password;
use tiny_auth_business::data::password::inject::dispatching_password_store;
use tiny_auth_business::data::password::Password;
use tiny_auth_business::store::password_store::PasswordStore;
use tiny_auth_business::store::UserStore;
use tiny_auth_test_fixtures::authenticator::authenticator;
use tiny_auth_test_fixtures::clock::clock;
use tiny_auth_test_fixtures::data::client::CONFIDENTIAL_CLIENT;
use tiny_auth_test_fixtures::data::password::in_place_password_store;
use tiny_auth_test_fixtures::data::user::USER_1;
use tiny_auth_test_fixtures::store::password_store::FailingPasswordStore;
use tiny_auth_test_fixtures::store::user_store::{build_test_user_store, TestUserStore, USER};
use tiny_auth_test_fixtures::token::build_test_rate_limiter;

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
    let client = CONFIDENTIAL_CLIENT.clone();
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
    let client = CONFIDENTIAL_CLIENT.clone();
    let actual_password = Password::Plain(client.client_id.to_owned());
    let password_to_check = "different";

    let actual = uut
        .authenticate_client(&client, &actual_password, password_to_check)
        .await
        .unwrap();

    assert!(!actual);
}

#[test(tokio::test)]
async fn password_store_error_is_propagated() {
    let store_name = String::from("fail");
    let uut = inject::authenticator(
        Arc::new(TestUserStore::from_iter([USER_1.clone()])),
        Arc::new(build_test_rate_limiter()),
        Arc::new(dispatching_password_store(
            [(
                store_name.clone(),
                Arc::new(FailingPasswordStore) as Arc<dyn PasswordStore>,
            )],
            Arc::new(in_place_password_store()),
        )),
        clock(),
    );

    let actual = uut
        .authenticate_client(
            &CONFIDENTIAL_CLIENT,
            &Password::Ldap { name: store_name },
            "password",
        )
        .await;

    assert!(matches!(
        actual,
        Err(PasswordStoreError(password::Error::BackendError)),
    ));
}
