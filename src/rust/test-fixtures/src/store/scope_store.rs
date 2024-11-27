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

use async_trait::async_trait;
use std::sync::Arc;
use tiny_auth_business::data::scope::Scope;
use tiny_auth_business::store::{ScopeStore, ScopeStoreError};

struct TestScopeStore {}

#[async_trait]
impl ScopeStore for TestScopeStore {
    async fn get_all(&self, keys: &[String]) -> Result<Vec<Scope>, ScopeStoreError> {
        Ok(keys
            .iter()
            .map(|v| Scope::new(v.as_str(), v.as_str(), v.as_str()))
            .collect())
    }
    async fn get_scope_names(&self) -> Result<Vec<String>, ScopeStoreError> {
        Ok(Vec::new())
    }
}

pub fn build_test_scope_store() -> Arc<impl ScopeStore> {
    Arc::new(TestScopeStore {})
}
