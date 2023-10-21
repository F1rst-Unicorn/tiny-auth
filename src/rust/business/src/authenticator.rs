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
use crate::password::Password;
use crate::rate_limiter::RateLimiter;
use crate::store::UserStore;
use crate::user::User;
use chrono::Local;
use log::debug;
use log::warn;
use std::sync::Arc;

#[derive(Clone)]
pub struct Authenticator {
    user_store: Arc<dyn UserStore>,

    rate_limiter: Arc<RateLimiter>,

    pepper: String,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rate limited")]
    RateLimited,
    #[error("username or password wrong")]
    WrongCredentials,
}

impl Authenticator {
    pub fn new(
        user_store: Arc<dyn UserStore>,
        rate_limiter: Arc<RateLimiter>,
        pepper: &str,
    ) -> Self {
        Self {
            user_store,
            rate_limiter,
            pepper: pepper.to_string(),
        }
    }

    pub async fn authenticate_user_and_forget(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(), Error> {
        self.authenticate_user(username, password).await.map(|_| ())
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<User, Error> {
        let user = match self.user_store.get(username) {
            None => {
                debug!("user '{}' not found", username);
                return Err(Error::WrongCredentials);
            }
            Some(u) => u,
        };

        let now = Local::now();
        self.rate_limiter.record_event(username, now).await;

        if self.rate_limiter.is_rate_above_maximum(username, now).await {
            warn!("User '{}' tried to authenticate too often", username);
            self.rate_limiter.remove_event(username, now).await;
            return Err(Error::RateLimited);
        }

        if user.is_password_correct(password, &self.pepper) {
            self.rate_limiter.remove_event(username, now).await;
            Ok(user)
        } else {
            debug!("password of user '{}' wrong", username);
            Err(Error::WrongCredentials)
        }
    }

    pub fn authenticate_client(&self, client: &Client, password: &str) -> bool {
        client.is_password_correct(password, &self.pepper)
    }

    pub fn construct_password(&self, username: &str, password: &str) -> Password {
        Password::new(username, password, &self.pepper)
    }
}
