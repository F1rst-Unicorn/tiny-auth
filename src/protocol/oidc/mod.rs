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

use super::oauth2::ProtocolError as OAuth2Error;
use super::oauth2::ResponseType as OAuth2ResponseType;

use std::convert::TryFrom;
use std::fmt::Display;

use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseType {
    OAuth2(OAuth2ResponseType),
    Oidc(OidcResponseType),
}

impl TryFrom<&str> for ResponseType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let result = match value {
            "code" => ResponseType::OAuth2(OAuth2ResponseType::Code),
            "token" => ResponseType::OAuth2(OAuth2ResponseType::Token),
            "id_token" => ResponseType::Oidc(OidcResponseType::IdToken),
            _ => return Err(format!("invalid response_type {}", value)),
        };

        Ok(result)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OidcResponseType {
    IdToken,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    error: ProtocolError,

    error_description: Option<String>,

    error_uri: Option<String>,

    state: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtocolError {
    OAuth2(OAuth2Error),
    Oidc(OidcProtocolError),
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            ProtocolError::OAuth2(e) => write!(f, "{}", e),
            ProtocolError::Oidc(e) => write!(f, "{}", e),
        }
    }
}

impl From<OAuth2Error> for ProtocolError {
    fn from(e: OAuth2Error) -> Self {
        Self::OAuth2(e)
    }
}

impl From<OidcProtocolError> for ProtocolError {
    fn from(e: OidcProtocolError) -> Self {
        Self::Oidc(e)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OidcProtocolError {
    #[serde(rename = "interaction_required")]
    InteractionRequired,
    #[serde(rename = "login_required")]
    LoginRequired,
    #[serde(rename = "account_selection_required")]
    AccountSelectionRequired,
    #[serde(rename = "consent_required")]
    ConsentRequired,
    #[serde(rename = "invalid_request_uri")]
    InvalidRequestUri,
    #[serde(rename = "invalid_request_object")]
    InvalidRequestObject,
    #[serde(rename = "request_not_supported")]
    RequestNotSupported,
    #[serde(rename = "request_uri_not_supported")]
    RequestUriNotSupported,
    #[serde(rename = "registration_not_supported")]
    RegistrationNotSupported,
}

impl Display for OidcProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let value = match self {
            OidcProtocolError::InteractionRequired => "interaction_required",
            OidcProtocolError::LoginRequired => "login_required",
            OidcProtocolError::AccountSelectionRequired => "account_selection_required",
            OidcProtocolError::ConsentRequired => "consent_required",
            OidcProtocolError::InvalidRequestUri => "invalid_request_uri",
            OidcProtocolError::InvalidRequestObject => "invalid_request_object",
            OidcProtocolError::RequestNotSupported => "request_not_supported",
            OidcProtocolError::RequestUriNotSupported => "request_uri_not_supported",
            OidcProtocolError::RegistrationNotSupported => "registration_not_supported",
        };
        write!(f, "{}", value)
    }
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl TryFrom<&str> for Prompt {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "none" => Ok(Prompt::None),
            "login" => Ok(Prompt::Login),
            "consent" => Ok(Prompt::Consent),
            "select_account" => Ok(Prompt::SelectAccount),
            _ => Err(()),
        }
    }
}
