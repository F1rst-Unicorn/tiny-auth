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

use crate::protocol::oauth2::ProtocolError as OAuth2Error;

pub enum ProtocolError {
    OAuth2Error(OAuth2Error),
    OidcError(OidcProtocolError),
}

pub enum OidcProtocolError {
    InteractionRequired,
    LoginRequired,
    AccountSelectionRequired,
    ConsentRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
    RegistrationNotSupported,
}
