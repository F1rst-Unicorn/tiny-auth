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

use tonic::metadata::MetadataMap;
use tracing::debug;

pub const AUTHORIZATION_HEADER_KEY: &str = "x-authorization";
const AUTHORIZATION_HEADER_BEARER_VALUE: &str = "Bearer ";

pub(crate) async fn extract_token(metadata: &MetadataMap) -> Option<&str> {
    let value = match metadata.get(AUTHORIZATION_HEADER_KEY) {
        None => {
            debug!("request has no {} header", AUTHORIZATION_HEADER_KEY);
            return None;
        }
        Some(v) => v,
    };

    let value = match value.to_str() {
        Err(e) => {
            debug!("value contains unprintable characters: {}", e);
            return None;
        }
        Ok(v) => v,
    };

    if !value.starts_with(AUTHORIZATION_HEADER_BEARER_VALUE) {
        debug!("value is not a bearer token");
        return None;
    }

    Some(
        value
            .split_once(' ')
            .expect("existence of space was validated before")
            .1,
    )
}
