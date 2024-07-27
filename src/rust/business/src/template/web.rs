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
use crate::template::web::AuthenticateError::{
    MissingPassword, MissingUsername, RateLimit, WrongCredentials,
};
use crate::template::{InstantiatedTemplate, Templater};
use tracing::error;

pub trait WebTemplater<Context: Send + Sync>: Templater<Context> {
    fn instantiate_error_page(&self, error: ErrorPage) -> InstantiatedTemplate;
}

pub struct WebappRootContext {
    pub provider_url: String,
    pub api_url: String,
    pub web_base: String,
}

pub struct AuthenticateContext {
    pub tries_left: u64,
    pub login_hint: String,
    pub error: Option<AuthenticateError>,
    pub csrf_token: String,
}

#[derive(Eq, PartialEq)]
pub enum AuthenticateError {
    MissingUsername,
    MissingPassword,
    WrongCredentials,
    RateLimit,
}

impl From<u8> for AuthenticateError {
    fn from(value: u8) -> Self {
        match value {
            1 => MissingUsername,
            2 => MissingPassword,
            3 => WrongCredentials,
            4 => RateLimit,
            _ => {
                error!(value, "relying on default code");
                WrongCredentials
            }
        }
    }
}

impl From<AuthenticateError> for u8 {
    fn from(value: AuthenticateError) -> Self {
        match value {
            MissingUsername => 1,
            MissingPassword => 2,
            WrongCredentials => 3,
            RateLimit => 4,
        }
    }
}

impl AuthenticateError {
    pub fn message(&self) -> &str {
        match self {
            MissingUsername => "Missing username",
            MissingPassword => "Missing password",
            WrongCredentials => "Username or password wrong",
            RateLimit => "You tried to log in too often.\nPlease come back again later.",
        }
    }
}

pub enum ErrorPage {
    ServerError,
    InvalidAuthenticationRequest,
    InvalidClientId,
    InvalidConsentRequest,
    InvalidRedirectUri,
}

impl ErrorPage {
    pub fn id(&self) -> &str {
        if let ErrorPage::InvalidRedirectUri = self {
            "invalid_redirect_uri"
        } else {
            ""
        }
    }

    pub fn title(&self) -> &str {
        match self {
            ErrorPage::ServerError => "Server Error",
            ErrorPage::InvalidAuthenticationRequest => "Invalid Authentication Request",
            ErrorPage::InvalidClientId => "Invalid Client ID",
            ErrorPage::InvalidConsentRequest => "Invalid Consent Request",
            ErrorPage::InvalidRedirectUri => "Invalid Redirect URI",
        }
    }
}
