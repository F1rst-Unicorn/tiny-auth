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

use crate::authenticate::Authenticator;
use crate::authenticate::AuthenticatorDispatcher;
use crate::connect::Connector;
use async_trait::async_trait;
use tiny_auth_business::health::HealthCheckCommand;
use tracing::warn;

pub struct LdapHealth {
    pub(crate) connector: Connector,
    pub(crate) authenticator: AuthenticatorDispatcher,
}

#[async_trait]
impl HealthCheckCommand for LdapHealth {
    async fn check(&self) -> bool {
        match self.connector.connect().await {
            Err(e) => {
                warn!(%e, "ldap health check failed");
                false
            }
            Ok(mut ldap) => self.authenticator.check(&mut ldap).await,
        }
    }
}
