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

pub mod authenticator;
pub mod authorize_endpoint;
pub mod change_password;
pub mod clock;
pub mod consent;
pub mod cors;
pub mod data;
pub mod data_loader;
#[cfg(test)]
pub mod data_loader_test;
pub mod health;
pub mod issuer_configuration;
pub mod json_pointer;
pub mod oauth2;
pub mod oidc;
pub mod pkce;
pub mod rate_limiter;
pub mod serde;
pub mod store;
pub mod template;
pub mod token;
pub mod token_endpoint;
pub mod userinfo_endpoint;
pub mod util;
