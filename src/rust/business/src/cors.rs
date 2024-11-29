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
use tracing::debug;
use url::Url;

pub trait CorsLister: Send + Sync {
    fn is_cors_allowed(&self, domain: &str) -> bool;
}

struct CorsListerImpl {
    approved_domains: Vec<Url>,
}

impl CorsLister for CorsListerImpl {
    fn is_cors_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = Url::parse(domain) else {
            debug!(domain, "no valid domain");
            return false;
        };
        debug!(%domain, "cors check");
        self.approved_domains.iter().any(|v| *v == domain)
    }
}

pub mod inject {
    use super::*;
    use url::Url;
    pub fn cors_lister(approved_domains: Vec<Url>) -> impl CorsLister {
        CorsListerImpl { approved_domains }
    }
}
