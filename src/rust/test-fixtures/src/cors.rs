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

use std::sync::Arc;
use tiny_auth_business::cors::CorsLister;

const VALID_CORS_DOMAIN: &str = "http://valid.example";

struct TestCorsLister {}

impl CorsLister for TestCorsLister {
    fn is_cors_allowed(&self, domain: &str) -> bool {
        domain == VALID_CORS_DOMAIN
    }
}

pub fn cors_lister() -> Arc<dyn CorsLister> {
    Arc::new(TestCorsLister {})
}