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
use crate::tiny_auth_proto::password_change_response::HashedPassword;
use crate::tiny_auth_proto::tiny_auth_api_server::TinyAuthApi;
use crate::tiny_auth_proto::HashedPasswordPbkdf2HmacSha256;
use crate::tiny_auth_proto::PasswordChangeRequest;
use crate::tiny_auth_proto::PasswordChangeResponse;
use async_trait::async_trait;
use tonic::Request;
use tonic::Response;

#[derive(Default)]
pub(crate) struct TinyAuthApiImpl {}

#[async_trait]
impl TinyAuthApi for TinyAuthApiImpl {
    async fn change_password(
        &self,
        request: Request<PasswordChangeRequest>,
    ) -> Result<Response<PasswordChangeResponse>, tonic::Status> {
        if !auth::authenticate_token(request.metadata()).await {
            return Err(tonic::Status::unauthenticated("unauthenticated"));
        }
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
