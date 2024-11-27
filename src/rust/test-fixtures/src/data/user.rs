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

use lazy_static::lazy_static;
use tiny_auth_business::data::password::Password;
use tiny_auth_business::data::user::User;

pub trait UserExt {
    fn with_allowed_scopes<'a, 'b, C, S>(
        self,
        scopes: impl IntoIterator<Item = (&'a C, impl IntoIterator<Item = &'b S>)>,
    ) -> Self
    where
        C: ToOwned<Owned = String> + ?Sized + 'a,
        S: ToOwned<Owned = String> + ?Sized + 'b;
}

impl UserExt for User {
    fn with_allowed_scopes<'a, 'b, C, S>(
        mut self,
        scopes: impl IntoIterator<Item = (&'a C, impl IntoIterator<Item = &'b S>)>,
    ) -> Self
    where
        C: ToOwned<Owned = String> + ?Sized + 'a,
        S: ToOwned<Owned = String> + ?Sized + 'b,
    {
        self.allowed_scopes = scopes
            .into_iter()
            .map(|(client_id, scopes)| {
                (
                    client_id.to_owned(),
                    scopes.into_iter().map(|v| v.to_owned()).collect(),
                )
            })
            .collect();
        self
    }
}

lazy_static! {
    pub static ref DEFAULT_USER: User = User {
        name: Default::default(),
        password: Password::Plain(String::new()),
        allowed_scopes: Default::default(),
        attributes: Default::default(),
    };
    pub static ref USER_1: User = serde_yaml::from_str(
        r#"
---
name: john
password:
  Pbkdf2HmacSha256:
    credential: iWUVg0T0npFqraL7frcoddhxQqkeL939abeUdq6LLMA=
    iterations: 100000
    salt: EkhhHSTv8lHJ0rICs1eRm88gw1KvyWs8D5x23M5+VYdqb2hu

email: john@test.example
email_verified: true
phone_number: +123456789
phone_number_verified: true
address: |
  Main Street 14
  11111 Portland
given_name: John
family_name: Doe
nickname: Jonny
preferred_username: doej
profile: ""
picture: ""
website: ""
gender: diverse
birthdate: 1991-09-11
zoneinfo: Europe/Berlin
locale: en-US
updated_at: 0
groups:
  - test
"#
    )
    .unwrap();
}
