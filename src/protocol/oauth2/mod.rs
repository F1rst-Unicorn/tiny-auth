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

pub enum ClientType {
    Public,
    Confidential,
}

pub enum GrantType {
    AuthorizationCode,
    Password,
    ClientCredentials,
    RefreshToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ResponseType {
    #[serde(rename = "code")] 
    Code,

    #[serde(rename = "token")] 
    Token,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ProtocolError {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporaryUnavailable,
}

impl Display for ProtocolError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> { 
        let value = match self {
            ProtocolError::InvalidRequest => "invalid_request",
            ProtocolError::UnauthorizedClient=> "unauthorized_client",
            ProtocolError::AccessDenied=> "access_denied",
            ProtocolError::UnsupportedResponseType=> "unsupported_response_type",
            ProtocolError::InvalidScope=> "invalid_scope",
            ProtocolError::ServerError=> "server_error",
            ProtocolError::TemporaryUnavailable=> "temporary_unavailable",
        };
        write!(f, "{}", value)
    }
}