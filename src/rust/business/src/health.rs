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

pub struct HealthChecker(pub Vec<HealthCheck>);

impl HealthChecker {
    pub async fn execute_all(&self) -> Vec<HealthStatement> {
        let mut result = Vec::default();
        for check in &self.0 {
            result.push(check.execute().await);
        }
        result
    }
}

pub struct HealthCheck {
    name: String,
    command: Arc<dyn HealthCheckCommand>,
}

impl HealthCheck {
    pub async fn execute(&self) -> HealthStatement {
        HealthStatement {
            name: self.name.clone(),
            state: self.command.check().await,
        }
    }
}

pub struct HealthStatement {
    pub name: String,
    pub state: bool,
}

#[async_trait]
pub trait HealthCheckCommand: Send + Sync {
    async fn check(&self) -> bool;
}

pub mod inject {
    use super::*;
    use std::sync::Arc;

    pub fn health_check(name: &str, command: Arc<dyn HealthCheckCommand>) -> HealthCheck {
        HealthCheck {
            name: name.to_string(),
            command,
        }
    }
}
