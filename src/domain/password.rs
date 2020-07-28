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

use std::num::NonZeroU32;

use ring::digest;
use ring::pbkdf2;

use base64::decode;
use base64::encode;

use rand::random;

use serde::Deserialize;
use serde::Serialize;

use log::error;

const HASH_ITERATIONS: u32 = 100_000;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Password {
    Pbkdf2HmacSha256 {
        credential: String,

        iterations: NonZeroU32,

        salt: String,
    },

    #[serde(alias = "plain")]
    Plain(String),
}

impl Password {
    pub fn new(username: &str, password: &str, pepper: &str) -> Self {
        let salt = generate_salt(username);
        let mut salt_and_pepper = salt.clone();
        salt_and_pepper.extend(pepper.as_bytes());
        let mut credentials = [0u8; digest::SHA256_OUTPUT_LEN];
        let iterations = NonZeroU32::new(HASH_ITERATIONS).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt_and_pepper,
            password.as_bytes(),
            &mut credentials,
        );
        Self::Pbkdf2HmacSha256 {
            credential: encode(credentials),
            iterations,
            salt: encode(salt),
        }
    }

    pub fn verify(&self, username: &str, password: &str, pepper: &str) -> bool {
        match self {
            Self::Plain(stored_password) => stored_password == password,
            Self::Pbkdf2HmacSha256 {
                credential,
                iterations,
                salt,
            } => {
                let credential = match decode(credential) {
                    Err(e) => {
                        error!("Failed to decode credential of user '{}': {}", username, e);
                        return false;
                    }
                    Ok(v) => v,
                };

                let salt = match decode(salt) {
                    Err(e) => {
                        error!("Failed to decode salt of user '{}': {}", username, e);
                        return false;
                    }
                    Ok(v) => v,
                };

                let mut salt_and_pepper = salt;
                salt_and_pepper.extend(pepper.as_bytes());

                pbkdf2::verify(
                    pbkdf2::PBKDF2_HMAC_SHA256,
                    *iterations,
                    &salt_and_pepper,
                    password.as_bytes(),
                    &credential,
                )
                .is_ok()
            }
        }
    }
}

fn generate_salt(username: &str) -> Vec<u8> {
    const RANDOM_SALT_LENGTH: usize = 32;
    let random_salt: [u8; RANDOM_SALT_LENGTH] = random();
    let mut result = Vec::with_capacity(RANDOM_SALT_LENGTH + username.len());
    result.extend(&random_salt);
    result.extend(username.as_bytes());
    result
}

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    pub fn passwords_can_be_verified() {
        let pw = Password::new("username", "password", "pepper");

        assert!(pw.verify("username", "password", "pepper"))
    }
}
