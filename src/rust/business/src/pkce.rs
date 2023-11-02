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

//! [RFC](https://www.rfc-editor.org/rfc/rfc7636)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;
use ring::digest::digest;
use ring::digest::SHA256;
use std::borrow::Cow;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid character")]
    InvalidCharacter,
}

#[derive(PartialEq, Eq)]
pub struct CodeChallenge<'a>(Cow<'a, str>);

const PATTERN: &str = "^[-a-zA-Z0-9._~]+$";

impl<'a> TryFrom<&'a str> for CodeChallenge<'a> {
    type Error = Error;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let pattern = Regex::new(PATTERN).unwrap();
        if value.len() < 43 || value.len() > 128 {
            Err(Error::InvalidLength)
        } else if !pattern.is_match(value) {
            Err(Error::InvalidCharacter)
        } else {
            Ok(CodeChallenge(Cow::Borrowed(value)))
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct CodeVerifier<'a>(Cow<'a, str>);

impl<'a> TryFrom<&'a str> for CodeVerifier<'a> {
    type Error = Error;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let pattern = Regex::new(PATTERN).unwrap();
        if value.len() < 43 || value.len() > 128 {
            Err(Error::InvalidLength)
        } else if !pattern.is_match(value) {
            Err(Error::InvalidCharacter)
        } else {
            Ok(CodeVerifier(Cow::Borrowed(value)))
        }
    }
}

impl<'a> From<CodeVerifier<'a>> for CodeChallenge<'a> {
    fn from(val: CodeVerifier<'a>) -> Self {
        CodeChallenge(Cow::Owned(
            URL_SAFE_NO_PAD.encode(digest(&SHA256, val.0.as_bytes())),
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::pkce::CodeChallenge;
    use std::borrow::Cow;

    #[test]
    pub fn learning_test_cow_eq() {
        assert_eq!(Cow::Owned::<str>("abc".to_string()), Cow::Borrowed("abc"));
    }

    #[test]
    pub fn valid_code_challenges_are_converted() {
        assert!(CodeChallenge::try_from("gfBGhTnM-57jV7buSQcDkmizJPPtIxJSJFjL0VHkS4s").is_ok());
    }
}
