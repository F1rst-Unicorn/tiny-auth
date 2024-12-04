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

use jsonwebtoken::Algorithm;

#[derive(Clone)]
pub struct IssuerConfiguration {
    pub issuer_url: String,

    pub algorithm: Algorithm,
}

impl IssuerConfiguration {
    pub fn jwks(&self) -> String {
        self.issuer_url.clone() + "/jwks"
    }

    pub fn token(&self) -> String {
        self.issuer_url.clone() + "/token"
    }

    pub fn get_key_type(&self) -> String {
        match self.algorithm {
            Algorithm::ES384 => "EC".to_owned(),
            Algorithm::PS512 => "RSA".to_owned(),
            _ => {
                unimplemented!("unsupported token algorithm");
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::issuer_configuration::*;
    use test_log::test;

    #[test]
    fn token_url_is_formed() {
        let uut = IssuerConfiguration {
            issuer_url: String::from("http://localhost/path"),
            algorithm: Algorithm::PS512,
        };

        assert_eq!(format!("{}{}", uut.issuer_url, "/token"), uut.token());
    }

    #[test]
    fn rsa_algorithm_is_mapped() {
        let uut = IssuerConfiguration {
            issuer_url: String::from("http://localhost/path"),
            algorithm: Algorithm::PS512,
        };

        assert_eq!("RSA", uut.get_key_type());
    }

    #[test]
    fn ec_algorithm_is_mapped() {
        let uut = IssuerConfiguration {
            issuer_url: String::from("http://localhost/path"),
            algorithm: Algorithm::ES384,
        };

        assert_eq!("EC", uut.get_key_type());
    }
}
