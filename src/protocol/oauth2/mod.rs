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

use serde_derive::Deserialize;
use serde_derive::Serialize;

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

#[derive(Deserialize)]
pub enum ResponseType {
    #[serde(rename = "code")] 
    Code,

    #[serde(rename = "token")] 
    Token,
}

#[derive(Serialize)]
pub enum ProtocolError {
    #[serde(rename = "invalid_request")]
    InvalidRequest,

    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporaryUnavailable,
}
