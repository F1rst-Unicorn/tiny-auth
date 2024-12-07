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
use serde_derive::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::{Display, Formatter};

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
    #[error("invalid character")]
    InvalidCharacter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug, Clone)]
pub struct CodeChallenge(CodeChallengeMethod, String);

const PATTERN: &str = "^[-a-zA-Z0-9._~]+$";

impl TryFrom<&String> for CodeChallenge {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        #[expect(
            clippy::unwrap_used,
            reason = "the validity of the regex is checked by tests"
        )]
        let pattern = Regex::new(PATTERN).unwrap();
        if value.len() < 43 || value.len() > 128 {
            Err(Error::InvalidLength)
        } else if !pattern.is_match(value) {
            Err(Error::InvalidCharacter)
        } else {
            Ok(CodeChallenge(CodeChallengeMethod::SHA256, value.to_owned()))
        }
    }
}

impl CodeChallenge {
    /// # Safety
    /// Use only to reconstruct an instance that was formerly validated by one of the safe
    /// constructors, e.g. when reinstantiating it from a persisted form.
    pub unsafe fn from_parts(
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
    ) -> Self {
        Self(code_challenge_method, code_challenge)
    }

    pub fn verify(&self, val: CodeVerifier) -> bool {
        match self.0 {
            CodeChallengeMethod::Plain => self.1 == val.0,
            CodeChallengeMethod::SHA256 => self.1 == Cow::<str>::Owned(Self::hash(val.0)),
        }
    }

    fn hash(value: Cow<str>) -> String {
        URL_SAFE_NO_PAD.encode(digest(&SHA256, value.as_bytes()))
    }

    pub fn code_challenge(&self) -> String {
        self.1.clone()
    }

    pub fn code_challenge_method(&self) -> CodeChallengeMethod {
        self.0
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct CodeVerifier<'a>(Cow<'a, str>);

impl<'a> TryFrom<&'a str> for CodeVerifier<'a> {
    type Error = Error;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        #[expect(
            clippy::unwrap_used,
            reason = "the validity of the regex is checked by tests"
        )]
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
    use super::*;
    use pretty_assertions::assert_eq;
    use std::borrow::Cow;
    use test_log::test;

    #[test]
    pub fn learning_test_cow_eq() {
        assert_eq!(Cow::Owned::<str>("abc".to_owned()), Cow::Borrowed("abc"));
    }

    #[test]
    pub fn short_challenges_are_rejected() {
        assert_eq!(
            Err(Error::InvalidLength),
            CodeVerifier::try_from(String::from("a").repeat(42).as_str())
        );
        assert_eq!(
            Err(Error::InvalidLength),
            CodeVerifier::try_from(String::from("a").repeat(129).as_str())
        );
    }

    #[test]
    pub fn valid_plain_challenge_validates() {
        let challenge = CodeChallenge(CodeChallengeMethod::Plain, "hello".to_owned());
        assert!(challenge.verify(CodeVerifier(Cow::Borrowed(challenge.1.as_str()))));
    }

    #[test]
    pub fn invalid_plain_challenge_is_rejected() {
        let challenge = CodeChallenge(CodeChallengeMethod::Plain, "hello".to_owned());
        assert!(!challenge.verify(CodeVerifier(Cow::Borrowed("bye"))));
    }

    #[test]
    pub fn valid_s256_challenge_validates() {
        let verifier = Cow::Borrowed("verifier");
        let raw_challenge = CodeChallenge::hash(verifier.clone());
        let challenge = CodeChallenge(CodeChallengeMethod::SHA256, raw_challenge);
        assert!(challenge.verify(CodeVerifier(verifier)));
    }

    #[test]
    pub fn invalid_s256_challenge_is_rejected() {
        let verifier = Cow::Borrowed("verifier");
        let raw_challenge = CodeChallenge::hash(verifier);
        let challenge = CodeChallenge(CodeChallengeMethod::SHA256, raw_challenge);
        assert!(!challenge.verify(CodeVerifier(Cow::Borrowed("different"))));
    }

    #[test]
    pub fn valid_code_challenges_are_converted() {
        assert!(
            CodeChallenge::try_from(&"gfBGhTnM-57jV7buSQcDkmizJPPtIxJSJFjL0VHkS4s".to_owned())
                .is_ok()
        );
    }
}
