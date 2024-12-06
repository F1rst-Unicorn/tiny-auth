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
use crate::data::password::Password;
use crate::token::{Access, Token, TokenValidator};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{span, Instrument, Level};

#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(
        &self,
        current_password: &str,
        new_password: &str,
        token: &str,
    ) -> Result<Password, Error>;
}

pub struct HandlerImpl<Authenticator> {
    pub(crate) authenticator: Arc<Authenticator>,
    pub(crate) token_validator: Arc<TokenValidator>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("password authentication: {0}")]
    PasswordAuthentication(#[from] crate::authenticator::Error),
    #[error("password construction: {0}")]
    PasswordConstruction(#[from] crate::store::password_store::PasswordConstructionError),
    #[error("token authentication")]
    TokenAuthentication,
}

pub mod inject {
    use crate::authenticator::Authenticator;
    use crate::change_password::{Handler, HandlerImpl};
    use crate::token::TokenValidator;
    use std::sync::Arc;

    pub fn handler<A>(authenticator: Arc<A>, token_validator: Arc<TokenValidator>) -> impl Handler
    where
        A: Authenticator,
    {
        HandlerImpl {
            authenticator,
            token_validator,
        }
    }
}

#[async_trait]
impl<A: Authenticator> Handler for HandlerImpl<A> {
    async fn handle(
        &self,
        current_password: &str,
        new_password: &str,
        token: &str,
    ) -> Result<Password, Error> {
        let token = self
            .token_validator
            .validate::<Token<Access>>(token)
            .ok_or(Error::TokenAuthentication)?;
        let cid_span = span!(Level::DEBUG, "cid", user = token.subject);
        let user = self
            .authenticator
            .authenticate_user(&token.subject, current_password)
            .instrument(cid_span.clone())
            .await?;
        Ok(self
            .authenticator
            .construct_password(user, new_password)
            .instrument(cid_span)
            .await?)
    }
}
