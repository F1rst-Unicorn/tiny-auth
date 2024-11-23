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

use crate::inject::{bind_dn_templater, ldap_search_templater};
use pretty_assertions::assert_eq;
use test_log::test;
use tiny_auth_business::template::bind_dn::BindDnContext;
use tiny_auth_business::template::ldap_search::LdapSearchContext;

#[test]
pub fn bind_dn_is_formatted() {
    let context = BindDnContext {
        user: "john".to_owned(),
    };
    let uut = bind_dn_templater("cn={{ user }},ou=users,dc=example,dc=org");

    let actual = uut.instantiate(context).unwrap();

    assert_eq!("cn=john,ou=users,dc=example,dc=org", actual.as_ref());
}

#[test]
pub fn ldap_search_is_formatted() {
    let context = LdapSearchContext {
        user: "john".to_owned(),
    };
    let uut = ldap_search_templater("(uid={{ user }})");

    let actual = uut.instantiate(context).unwrap();

    assert_eq!("(uid=john)", actual.as_ref());
}
