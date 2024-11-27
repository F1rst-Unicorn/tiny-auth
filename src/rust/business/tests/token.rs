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

#![expect(clippy::unwrap_used)] // this is test code

use pretty_assertions::assert_eq;
use serde_json::from_str;
use test_log::test;
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::store::UserStore;
use tiny_auth_business::token::{Audience, EncodedRefreshToken, TokenValidator};
use tiny_auth_test_fixtures::data::client::CONFIDENTIAL_CLIENT;
use tiny_auth_test_fixtures::data::client::TINY_AUTH_FRONTEND;
use tiny_auth_test_fixtures::store::client_store::build_test_client_store;
use tiny_auth_test_fixtures::store::user_store::build_test_user_store;
use tiny_auth_test_fixtures::store::user_store::USER;
use tiny_auth_test_fixtures::token::build_test_algorithm;
use tiny_auth_test_fixtures::token::build_test_decoding_key;
use tiny_auth_test_fixtures::token::build_test_token_creator;
use tiny_auth_test_fixtures::token::build_test_token_issuer;
use tracing::debug;

#[test]
pub fn deserialise_single_audience() {
    let input = r#""audience""#;

    match from_str::<Audience>(input) {
        Err(e) => {
            debug!(%e);
            panic!("invalid input");
        }
        Ok(audience) => {
            assert_eq!(Audience::Single("audience".to_owned()), audience);
        }
    }
}

#[test]
pub fn deserialise_list_audience() {
    let input = r#"["audience1","audience2"]"#;

    match from_str::<Audience>(input) {
        Err(e) => {
            debug!(%e);
            panic!("invalid input");
        }
        Ok(audience) => {
            assert_eq!(
                Audience::Several(vec!["audience1".to_owned(), "audience2".to_owned()]),
                audience
            );
        }
    }
}

#[test(tokio::test)]
pub async fn different_audience_is_rejected() {
    validate_audience(CONFIDENTIAL_CLIENT.client_id.as_str(), false).await;
}

#[test(tokio::test)]
pub async fn own_audience_is_accepted() {
    validate_audience(TINY_AUTH_FRONTEND.client_id.as_str(), true).await;
}

async fn validate_audience(audience: &str, expected: bool) {
    let token_creator = build_test_token_creator();
    let token = token_creator.build_token(
        &build_test_user_store().get(USER).await.unwrap(),
        &build_test_client_store().get(audience).await.unwrap(),
        &[],
        0,
    );
    let token = token_creator.finalize_access_token(token).unwrap();

    let actual = TokenValidator::new_for_own_api(
        build_test_decoding_key(),
        build_test_algorithm(),
        build_test_token_issuer(),
    )
    .validate_access_token(token);

    assert_eq!(expected, actual.is_some());
}

pub fn refresh_token(raw: String) -> EncodedRefreshToken {
    unsafe { EncodedRefreshToken::from_parts(raw) }
}
