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

use crate::clock::Clock;
use crate::data::client::Client;
use crate::data::password::{DispatchingPasswordStore, Password};
use crate::data::user::User;
use crate::rate_limiter::RateLimiter;
use crate::store::password_store::{PasswordConstructionError, PasswordStore};
use crate::store::UserStore;
use async_trait::async_trait;
use chrono::{DateTime, Local};
use std::sync::Arc;
use tracing::warn;
use tracing::{debug, instrument, Level};

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate_user_and_forget(
        &self,
        username: &str,
        password: &str,
    ) -> Result<DateTime<Local>, Error>;

    async fn authenticate_user(&self, username: &str, password: &str) -> Result<User, Error>;

    async fn authenticate_client(
        &self,
        client: &Client,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, Error>;

    async fn construct_password(
        &self,
        user: User,
        password: &str,
    ) -> Result<Password, PasswordConstructionError>;
}

#[derive(Clone)]
pub struct AuthenticatorImpl<Clock> {
    user_store: Arc<dyn UserStore>,

    password_store: Arc<DispatchingPasswordStore>,

    rate_limiter: Arc<RateLimiter>,

    clock: Clock,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rate limited")]
    RateLimited,
    #[error("username or password wrong")]
    WrongCredentials,
    #[error("{0}")]
    PasswordStoreError(#[from] crate::data::password::Error),
    #[error("{0}")]
    UserStoreError(#[from] crate::store::user_store::Error),
}

#[async_trait]
impl<C: Clock> Authenticator for AuthenticatorImpl<C> {
    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(user = username))]
    async fn authenticate_user_and_forget(
        &self,
        username: &str,
        password: &str,
    ) -> Result<DateTime<Local>, Error> {
        self.authenticate_user(username, password)
            .await
            .map(|_| self.clock.now())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<User, Error> {
        let user = match self.user_store.get(username).await {
            Err(e) => {
                debug!(%e, "not found");
                return Err(Error::WrongCredentials);
            }
            Ok(u) => u,
        };

        let now = self.clock.now();
        self.rate_limiter.record_event(username, now).await;

        if self.rate_limiter.is_rate_above_maximum(username, now).await {
            warn!("tried to authenticate too often");
            self.rate_limiter.remove_event(username, now).await;
            return Err(Error::RateLimited);
        }

        if self
            .password_store
            .verify(username, &user.password, password)
            .await?
        {
            self.rate_limiter.remove_event(username, now).await;
            Ok(user)
        } else {
            debug!("password wrong");
            Err(Error::WrongCredentials)
        }
    }

    async fn authenticate_client(
        &self,
        client: &Client,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, Error> {
        Ok(self
            .password_store
            .verify(&client.client_id, stored_password, password_to_check)
            .await?)
    }

    async fn construct_password(
        &self,
        user: User,
        password: &str,
    ) -> Result<Password, PasswordConstructionError> {
        self.password_store.construct_password(user, password).await
    }
}

pub mod inject {
    use super::*;

    pub fn authenticator<C>(
        user_store: Arc<dyn UserStore>,
        rate_limiter: Arc<RateLimiter>,
        password_store: Arc<DispatchingPasswordStore>,
        clock: C,
    ) -> impl Authenticator
    where
        C: Clock,
    {
        AuthenticatorImpl {
            user_store,
            rate_limiter,
            password_store,
            clock,
        }
    }
}
