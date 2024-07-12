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
use crate::error::LdapError;
use ldap3::{drive, Ldap, LdapConnAsync, LdapConnSettings};
use log::{debug, warn};
use std::time::Duration;
use url::Url;

pub struct Connector {
    pub(crate) urls: Vec<Url>,
    pub(crate) connect_timeout: Duration,
    pub(crate) starttls: bool,
}

impl Connector {
    pub(crate) async fn connect(&self) -> Result<Ldap, LdapError> {
        for url in &self.urls {
            let settings = LdapConnSettings::new()
                .set_conn_timeout(self.connect_timeout)
                .set_starttls(self.starttls);
            debug!("connecting to {}", &url);
            match LdapConnAsync::from_url_with_settings(settings, url).await {
                Err(e) => {
                    warn!("ldap connection to '{}' failed: {}", url, e);
                }
                Ok((conn, ldap)) => {
                    drive!(conn);
                    debug!("connected to {}", &url);
                    return Ok(ldap);
                }
            }
        }
        warn!("failed to connect to any backend");
        Err(LdapError::ConnectError)
    }
}
