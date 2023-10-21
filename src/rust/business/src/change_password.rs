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

use crate::authenticator::Authenticator;
use crate::password::Password;
use crate::token::{Token, TokenValidator};
use std::sync::Arc;

pub struct Handler {
    pub(crate) authenticator: Arc<Authenticator>,
    pub(crate) token_validator: Arc<TokenValidator>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("password authentication")]
    PasswordAuthentication(#[from] crate::authenticator::Error),
    #[error("token authentication")]
    TokenAuthentication,
}

impl Handler {
    pub fn new(authenticator: Arc<Authenticator>, token_validator: Arc<TokenValidator>) -> Self {
        Self {
            authenticator,
            token_validator,
        }
    }

    pub async fn handle(
        &self,
        current_password: &str,
        new_password: &str,
        token: &str,
    ) -> Result<Password, Error> {
        let token = self
            .token_validator
            .validate::<Token>(token)
            .ok_or(Error::TokenAuthentication)?;
        self.authenticator
            .authenticate_user(&token.subject, current_password)
            .await?;
        Ok(self
            .authenticator
            .construct_password(&token.subject, new_password))
    }
}
