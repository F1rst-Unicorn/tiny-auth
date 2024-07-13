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

use crate::endpoints::authorize;
use actix_session::Session;
use tiny_auth_business::authorize_endpoint::{AuthorizeRequestState, Error};
use tracing::error;

pub struct AuthorizeSession(Session);

impl From<Session> for AuthorizeSession {
    fn from(value: Session) -> Self {
        Self(value)
    }
}

impl tiny_auth_business::authorize_endpoint::Session for AuthorizeSession {
    fn store(&self, state: AuthorizeRequestState) -> Result<(), Error> {
        match self.0.insert(authorize::SESSION_KEY, state) {
            Err(e) => {
                error!("Failed to store authorize request: {e}");
                Err(Error::ServerError)
            }
            Ok(_) => Ok(()),
        }
    }
}
