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

use crate::tiny_auth_proto::password_change_response::HashedPassword;
use crate::tiny_auth_proto::HashedPasswordPbkdf2HmacSha256;
use crate::tiny_auth_proto::PasswordChangeRequest;
use crate::tiny_auth_proto::PasswordChangeResponse;
use std::sync::Arc;
use tiny_auth_business::password::PasswordVerifier;
use tonic::Request;
use tonic::Response;

pub(crate) struct Handler {
    pub(crate) password_verifier: Arc<PasswordVerifier>,
}

impl Handler {
    pub fn new(password_verifier: Arc<PasswordVerifier>) -> Self {
        Self { password_verifier }
    }

    pub async fn handle(
        &self,
        request: Request<PasswordChangeRequest>,
    ) -> Result<Response<PasswordChangeResponse>, tonic::Status> {
        let response = PasswordChangeResponse {
            hashed_password: Some(HashedPassword::Pbkdf2HmacSha256(
                HashedPasswordPbkdf2HmacSha256 {
                    credential: "credential".to_string(),
                    iterations: 1409,
                    salt: "salt".to_string(),
                },
            )),
        };
        Ok(Response::new(response))
    }
}
