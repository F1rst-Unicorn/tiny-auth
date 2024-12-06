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
#[cfg(test)]
use mockall::automock;
use std::sync::Arc;
use tracing::instrument;

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

#[derive(Clone)]
pub struct HealthCheck {
    name: String,
    command: Arc<dyn HealthCheckCommand>,
}

impl HealthCheck {
    #[instrument(skip_all, fields(name = self.name))]
    pub async fn execute(&self) -> HealthStatement {
        HealthStatement {
            name: self.name.clone(),
            state: self.command.check().await,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HealthStatement {
    pub name: String,
    pub state: bool,
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait HealthCheckCommand: Send + Sync {
    async fn check(&self) -> bool;
}

pub mod inject {
    use super::*;
    use std::sync::Arc;

    pub fn health_check(name: &str, command: Arc<dyn HealthCheckCommand>) -> HealthCheck {
        HealthCheck {
            name: name.to_owned(),
            command,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::health::*;
    use test_log::test;

    #[test(tokio::test)]
    async fn all_checks_are_executed() {
        let mut healthy_command = MockHealthCheckCommand::new();
        healthy_command.expect_check().times(1).return_const(true);
        let mut sick_command = MockHealthCheckCommand::new();
        sick_command.expect_check().times(1).return_const(false);
        let uut = HealthChecker(vec![
            inject::health_check("ok", Arc::new(healthy_command)),
            inject::health_check("nok", Arc::new(sick_command)),
        ]);

        assert_eq!(
            vec![
                HealthStatement {
                    name: "ok".into(),
                    state: true,
                },
                HealthStatement {
                    name: "nok".into(),
                    state: false,
                }
            ],
            uut.execute_all().await
        );
    }
}
