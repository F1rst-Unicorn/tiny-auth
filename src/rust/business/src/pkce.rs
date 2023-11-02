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
use std::fmt::{Display, Formatter};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid character")]
    InvalidCharacter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    Plain,
    SHA256,
}

impl TryFrom<&String> for CodeChallengeMethod {
    type Error = ();
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "plain" => Ok(CodeChallengeMethod::Plain),
            "S256" => Ok(CodeChallengeMethod::SHA256),
            _ => Err(()),
        }
    }
}

impl Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            CodeChallengeMethod::Plain => "plain",
            CodeChallengeMethod::SHA256 => "S256",
        };
        write!(f, "{}", value)
    }
}

#[derive(PartialEq, Eq)]
pub struct CodeChallenge(CodeChallengeMethod, String);

const PATTERN: &str = "^[-a-zA-Z0-9._~]+$";

impl TryFrom<&String> for CodeChallenge {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        let pattern = Regex::new(PATTERN).unwrap();
        if value.len() < 43 || value.len() > 128 {
            Err(Error::InvalidLength)
        } else if !pattern.is_match(value) {
            Err(Error::InvalidCharacter)
        } else {
            Ok(CodeChallenge(
                CodeChallengeMethod::SHA256,
                value.to_string(),
            ))
        }
    }
}

impl CodeChallenge {
    pub fn verify(&self, val: CodeVerifier) -> bool {
        match self.0 {
            CodeChallengeMethod::Plain => self.1 == val.0,
            CodeChallengeMethod::SHA256 => {
                self.1
                    == Cow::<str>::Owned(URL_SAFE_NO_PAD.encode(digest(&SHA256, val.0.as_bytes())))
            }
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
        assert!(CodeChallenge::try_from(
            &"gfBGhTnM-57jV7buSQcDkmizJPPtIxJSJFjL0VHkS4s".to_string()
        )
        .is_ok());
    }
}
