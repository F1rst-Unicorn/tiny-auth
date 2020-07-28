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

use crate::domain::Password;

use std::fmt::Display;

use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    error: ProtocolError,

    error_description: Option<String>,

    error_uri: Option<String>,

    state: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    #[serde(rename = "public")]
    Public,

    #[serde(rename = "confidential")]
    Confidential {
        password: Password,

        #[serde(alias = "public key")]
        public_key: Option<String>,
    },
}

#[derive(Deserialize, PartialEq, Eq)]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,

    #[serde(rename = "password")]
    Password,

    #[serde(rename = "client_credentials")]
    ClientCredentials,

    #[serde(rename = "refresh_token")]
    RefreshToken,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ResponseType {
    Code,
    Token,
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProtocolError {
    // https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    #[serde(rename = "invalid_request")]
    InvalidRequest,

    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,

    #[serde(rename = "access_denied")]
    AccessDenied,

    #[serde(rename = "unsupported_response_type")]
    UnsupportedResponseType,

    #[serde(rename = "invalid_scope")]
    InvalidScope,

    #[serde(rename = "server_error")]
    ServerError,

    #[serde(rename = "temporarily_unavailable")]
    TemporarilyUnavailable,

    // https://tools.ietf.org/html/rfc6749#section-5.2
    #[serde(rename = "invalid_client")]
    InvalidClient,

    #[serde(rename = "invalid_grant")]
    InvalidGrant,

    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let value = match self {
            ProtocolError::InvalidRequest => "invalid_request",
            ProtocolError::UnauthorizedClient => "unauthorized_client",
            ProtocolError::AccessDenied => "access_denied",
            ProtocolError::UnsupportedResponseType => "unsupported_response_type",
            ProtocolError::InvalidScope => "invalid_scope",
            ProtocolError::ServerError => "server_error",
            ProtocolError::TemporarilyUnavailable => "temporary_unavailable",
            ProtocolError::InvalidClient => "invalid_client",
            ProtocolError::InvalidGrant => "invalid_grant",
            ProtocolError::UnsupportedGrantType => "unsupported_grant_type",
        };
        write!(f, "{}", value)
    }
}
