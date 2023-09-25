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

use crate::auth;
use crate::tiny_auth_proto::tiny_auth_api_server::TinyAuthApi;
use crate::tiny_auth_proto::{HashedPasswordPbkdf2HmacSha256, PasswordChangeRequest};
use crate::tiny_auth_proto::PasswordChangeResponse;
use async_trait::async_trait;
use tonic::Request;
use tonic::Response;
use tiny_auth_business::password::Password;
use log::debug;
use log::error;
use crate::tiny_auth_proto::password_change_response::HashedPassword;

pub(crate) struct TinyAuthApiImpl {
    pub(crate) change_password: tiny_auth_business::change_password::Handler,
}

#[async_trait]
impl TinyAuthApi for TinyAuthApiImpl {
    async fn change_password(
        &self,
        request: Request<PasswordChangeRequest>,
    ) -> Result<Response<PasswordChangeResponse>, tonic::Status> {
        let token = match auth::extract_token(request.metadata()).await {
            None => {
                return Err(tonic::Status::unauthenticated("unauthenticated"));
            }
            Some(v) => v,
        };

        match self.change_password.handle(&request.into_inner().current_password, &request.into_inner().new_password, token).await {
            Err(e) => {
                debug!("changing password failed: {}", e);
                Err(tonic::Status::permission_denied("permission denied"))
            }
            Ok(Password::Pbkdf2HmacSha256 {
                credential,
                iterations,
                salt,
               }) => {
                let response = PasswordChangeResponse {
                    hashed_password: Some(HashedPassword::Pbkdf2HmacSha256(
                        HashedPasswordPbkdf2HmacSha256 {
                            credential,
                            iterations: iterations.get(),
                            salt
                        }
                    ))
                };
                Ok(Response::new(response))
            }
            Ok(Password::Plain(_)) => {
                error!("Changing password to plain is prohibited.");
                Err(tonic::Status::internal("internal error"))
            }
        }
    }
}