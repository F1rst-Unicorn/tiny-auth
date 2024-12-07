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
use crate::store::{ClientStore, ScopeStore, ScopeStoreError, UserStore};
use crate::token::{Access, EncodedAccessToken, Token, TokenCreator, TokenValidator, Userinfo};
use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

pub struct Request {
    pub token: EncodedAccessToken,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid token")]
    InvalidToken,
    #[error("user lookup error")]
    UserError(#[from] crate::store::user_store::Error),
    #[error("client lookup error")]
    ClientError(#[from] crate::store::client_store::Error),
    #[error("scope lookup error")]
    ScopeError(#[from] ScopeStoreError),
}

#[async_trait]
pub trait Handler: Send + Sync {
    async fn get_userinfo(&self, request: Request) -> Result<Token<Userinfo>, Error>;
}

pub struct HandlerImpl<TokenCreator> {
    token_validator: Arc<TokenValidator>,
    token_creator: TokenCreator,
    client_store: Arc<dyn ClientStore>,
    user_store: Arc<dyn UserStore>,
    scope_store: Arc<dyn ScopeStore>,
}

#[async_trait]
impl<T: TokenCreator> Handler for HandlerImpl<T> {
    async fn get_userinfo(&self, request: Request) -> Result<Token<Userinfo>, Error> {
        let token = match self
            .token_validator
            .validate::<Token<Access>>(request.token.as_ref())
        {
            None => {
                debug!("invalid token");
                return Err(Error::InvalidToken);
            }
            Some(v) => v,
        };

        let user = self.user_store.get(&token.subject).await?;
        let client = self.client_store.get(&token.authorized_party).await?;
        let scopes = self.scope_store.get_all(&token.scopes).await?;

        Ok(self.token_creator.build_token(&user, &client, &scopes, 0))
    }
}

pub mod inject {
    use crate::store::{ClientStore, ScopeStore, UserStore};
    use crate::token::{TokenCreator, TokenValidator};
    use crate::userinfo_endpoint::{Handler, HandlerImpl};
    use std::sync::Arc;

    pub fn handler<T>(
        token_validator: Arc<TokenValidator>,
        token_creator: T,
        client_store: Arc<dyn ClientStore>,
        user_store: Arc<dyn UserStore>,
        scope_store: Arc<dyn ScopeStore>,
    ) -> impl Handler
    where
        T: TokenCreator,
    {
        HandlerImpl {
            token_validator,
            token_creator,
            client_store,
            user_store,
            scope_store,
        }
    }
}