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

use crate::client::Client;
use crate::password::{DispatchingPasswordStore, Password};
use crate::rate_limiter::RateLimiter;
use crate::store::{PasswordConstructionError, PasswordStore, UserStore};
use crate::user::User;
use chrono::Local;
use std::sync::Arc;
use tracing::warn;
use tracing::{debug, instrument, Level};

#[derive(Clone)]
pub struct Authenticator {
    user_store: Arc<dyn UserStore>,

    password_store: Arc<DispatchingPasswordStore>,

    rate_limiter: Arc<RateLimiter>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rate limited")]
    RateLimited,
    #[error("username or password wrong")]
    WrongCredentials,
    #[error("{0}")]
    PasswordStoreError(#[from] crate::password::Error),
    #[error("{0}")]
    UserStoreError(#[from] crate::user::Error),
}

impl Authenticator {
    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(user = username))]
    pub async fn authenticate_user_and_forget(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), Error> {
        self.authenticate_user(username, password).await.map(|_| ())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<User, Error> {
        let user = match self.user_store.get(username).await {
            Err(e) => {
                debug!(%e, "not found");
                return Err(Error::WrongCredentials);
            }
            Ok(u) => u,
        };

        let now = Local::now();
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

    pub async fn authenticate_client(
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

    pub async fn construct_password(
        &self,
        user: User,
        password: &str,
    ) -> Result<Password, PasswordConstructionError> {
        self.password_store.construct_password(user, password).await
    }
}

pub mod inject {
    use super::*;

    pub fn authenticator(
        user_store: Arc<dyn UserStore>,
        rate_limiter: Arc<RateLimiter>,
        password_store: Arc<DispatchingPasswordStore>,
    ) -> Authenticator {
        Authenticator {
            user_store,
            rate_limiter,
            password_store,
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::password::test_fixtures::in_place_password_store;
    use crate::store::test_fixtures::{build_test_user_store, USER};
    use crate::store::{PasswordStore, UserStore};
    use test_log::test;

    #[test(tokio::test)]
    async fn own_constructed_password_is_verifiable() {
        let uut = super::test_fixtures::authenticator();
        let user = build_test_user_store().get(USER).await.unwrap();
        let new_password = "new-password";

        let actual = uut
            .construct_password(user.clone(), new_password)
            .await
            .unwrap();

        assert!(in_place_password_store()
            .verify(user.name.as_str(), &actual, new_password)
            .await
            .unwrap_or(false));
    }
}

pub mod test_fixtures {
    use crate::authenticator::Authenticator;
    use crate::password::inject::{dispatching_password_store, in_place_password_store};
    use crate::password::test_fixtures::PEPPER;
    use crate::store::test_fixtures::build_test_user_store;
    use crate::test_fixtures::build_test_rate_limiter;
    use std::sync::Arc;

    pub fn authenticator() -> Authenticator {
        super::inject::authenticator(
            build_test_user_store(),
            Arc::new(build_test_rate_limiter()),
            Arc::new(dispatching_password_store(
                Default::default(),
                Arc::new(in_place_password_store(PEPPER)),
            )),
        )
    }
}