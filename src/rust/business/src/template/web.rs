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
use crate::template::{InstantiatedTemplate, Templater};

pub trait WebTemplater<Context: Send + Sync>: Templater<Context> {
    fn instantiate_error_page(&self, error: ErrorPage) -> InstantiatedTemplate;
}

pub struct WebappRoot {
    pub provider_url: String,
    pub api_url: String,
    pub web_base: String,
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
