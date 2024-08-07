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

use crate::client::Client;
use crate::oidc::{OidcResponseType, Prompt, ResponseType};
use crate::pkce::{CodeChallenge, CodeChallengeMethod};
use crate::scope::parse_scope_names;
use crate::serde::deserialise_empty_as_none;
use crate::store::ClientStore;
use log::Level::Debug;
use log::{debug, info, log_enabled};
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Default)]
pub struct Request {
    pub scope: Option<String>,
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub login_hint: Option<String>,
    pub code_challenge_method: Option<String>,
    pub code_challenge: Option<String>,
}

pub enum Error {
    InvalidRedirectUri,
    InvalidClientId,
    MissingScopes { redirect_uri: String },
    ContradictingPrompts { redirect_uri: String },
    CodeChallengeMethodInvalid { redirect_uri: String },
    CodeChallengeInvalid { redirect_uri: String },
    MissingResponseType { redirect_uri: String },
    MissingNonceForImplicitFlow { redirect_uri: String },
    ServerError,
}

#[derive(Clone)]
pub struct Handler {
    client_store: Arc<dyn ClientStore>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthorizeRequestState {
    #[serde(default)]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_id: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prompts: Vec<Prompt>,

    #[serde(default)]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub redirect_uri: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub state: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub nonce: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub login_hint: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub encode_redirect_to_fragment: bool,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<ResponseType>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<CodeChallenge>,
}

pub trait Session {
    fn store(&self, state: AuthorizeRequestState) -> Result<(), Error>;
}

impl Handler {
    pub async fn handle(&self, request: Request, session: impl Session) -> Result<(), Error> {
        let redirect_uri = Self::extract_redirect_uri(request.redirect_uri)?;
        let client_id = Self::extract_client_id(request.client_id)?;
        let client = self.load_client(&client_id).await?;
        Self::ensure_client_supports_redirect_uri(&client, &redirect_uri)?;
        let scopes =
            Self::match_requested_scopes_with_client(&client, request.scope).map_err(|_| {
                Error::MissingScopes {
                    redirect_uri: redirect_uri.clone(),
                }
            })?;
        let prompts =
            Self::ensure_consistent_prompt_settings(request.prompt.as_deref()).map_err(|_| {
                Error::ContradictingPrompts {
                    redirect_uri: redirect_uri.clone(),
                }
            })?;
        let code_challenge = Self::validate_pkce(
            request.code_challenge,
            request.code_challenge_method,
            &redirect_uri,
        )?;
        let response_types = Self::parse_response_types(
            request.response_type,
            request.nonce.as_ref(),
            &redirect_uri,
        )?;
        session.store(AuthorizeRequestState {
            client_id,
            scopes,
            prompts: prompts.into_iter().collect(),
            redirect_uri,
            state: request.state,
            nonce: request.nonce,
            max_age: request.max_age,
            login_hint: request.login_hint,
            encode_redirect_to_fragment: ResponseType::encode_redirect_to_fragment(&response_types),
            response_types,
            code_challenge,
        })?;
        Ok(())
    }

    fn extract_redirect_uri(redirect_uri: Option<String>) -> Result<String, Error> {
        match redirect_uri {
            None => {
                debug!("missing redirect_uri");
                Err(Error::InvalidRedirectUri)
            }
            Some(redirect_uri) => Ok(redirect_uri),
        }
    }

    fn extract_client_id(client_id: Option<String>) -> Result<String, Error> {
        match client_id {
            None => {
                debug!("missing client_id");
                Err(Error::InvalidClientId)
            }
            Some(client_id) => Ok(client_id),
        }
    }

    async fn load_client(&self, client_id: &str) -> Result<Client, Error> {
        match self.client_store.get(client_id).await {
            Err(e) => {
                info!("client '{}' not found ({e})", client_id);
                Err(Error::InvalidClientId)
            }
            Ok(client) => Ok(client),
        }
    }

    fn ensure_client_supports_redirect_uri(
        client: &Client,
        redirect_uri: &str,
    ) -> Result<(), Error> {
        if !client.is_redirect_uri_valid(redirect_uri) {
            info!(
                "invalid redirect_uri '{}' for client '{}'",
                redirect_uri, client.client_id
            );
            Err(Error::InvalidRedirectUri)
        } else {
            Ok(())
        }
    }

    fn match_requested_scopes_with_client(
        client: &Client,
        scopes: Option<String>,
    ) -> Result<Vec<String>, ()> {
        let scopes = match scopes {
            None => {
                debug!("Missing scope");
                return Err(());
            }
            Some(scopes) => scopes,
        };

        let scopes: BTreeSet<String> = parse_scope_names(&scopes).into_iter().collect();

        if log_enabled!(Debug) {
            Self::log_removed_scopes(&client, &scopes);
        }

        Ok(scopes
            .intersection(&client.allowed_scopes)
            .map(Clone::clone)
            .collect::<Vec<String>>())
    }

    fn log_removed_scopes(client: &&Client, scopes: &BTreeSet<String>) {
        let forbidden_scopes = scopes
            .difference(&client.allowed_scopes)
            .map(Clone::clone)
            .collect::<Vec<String>>()
            .join(" ");
        if !forbidden_scopes.is_empty() {
            debug!(
                "Client '{}' requested forbidden scopes '{}'. These are dropped silently",
                client.client_id, forbidden_scopes
            );
        }
    }

    fn ensure_consistent_prompt_settings(prompt: Option<&str>) -> Result<BTreeSet<Prompt>, ()> {
        let prompts = Self::parse_prompt(prompt);
        if (prompts.contains(&Prompt::Login)
            || prompts.contains(&Prompt::Consent)
            || prompts.contains(&Prompt::SelectAccount))
            && prompts.contains(&Prompt::None)
        {
            debug!("Contradicting prompt requirements");
            Err(())
        } else {
            Ok(prompts)
        }
    }

    fn parse_prompt(prompt: Option<&str>) -> BTreeSet<Prompt> {
        match prompt {
            None => Default::default(),
            Some(value) => value.split(' ').flat_map(Prompt::try_from).collect(),
        }
    }

    fn validate_pkce(
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        redirect_uri: &str,
    ) -> Result<Option<CodeChallenge>, Error> {
        match (code_challenge.as_ref(), code_challenge_method.as_ref()) {
            (None, None) => Ok(None),
            (Some(challenge), Some(method)) => match CodeChallengeMethod::try_from(method) {
                Err(_) => {
                    debug!("unknown code_challenge_method '{method}'");
                    Err(Error::CodeChallengeMethodInvalid {
                        redirect_uri: redirect_uri.to_string(),
                    })
                }
                Ok(CodeChallengeMethod::Plain) => {
                    debug!("code_challenge_method {method} is insecure and not supported");
                    Err(Error::CodeChallengeMethodInvalid {
                        redirect_uri: redirect_uri.to_string(),
                    })
                }
                Ok(_) => match CodeChallenge::try_from(challenge) {
                    Err(e) => {
                        debug!("invalid code_challenge '{challenge}': {e}");
                        Err(Error::CodeChallengeInvalid {
                            redirect_uri: redirect_uri.to_string(),
                        })
                    }
                    Ok(v) => Ok(Some(v)),
                },
            },
            _ => {
                debug!("code_challenge and code_challenge_method must both be present or absent");
                Err(Error::CodeChallengeInvalid {
                    redirect_uri: redirect_uri.to_string(),
                })
            }
        }
    }

    fn parse_response_types(
        response_type: Option<String>,
        nonce: Option<&String>,
        redirect_uri: &str,
    ) -> Result<Vec<ResponseType>, Error> {
        let response_types = match response_type.as_deref().map(Self::parse_response_type) {
            None | Some(None) => {
                debug!("Missing or invalid response_type");
                return Err(Error::MissingResponseType {
                    redirect_uri: redirect_uri.to_string(),
                });
            }
            Some(Some(response_type)) => response_type,
        };

        // https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
        if response_types.contains(&ResponseType::Oidc(OidcResponseType::IdToken))
            && nonce.is_none()
        {
            debug!("Missing required parameter nonce for implicit flow");
            Err(Error::MissingNonceForImplicitFlow {
                redirect_uri: redirect_uri.to_string(),
            })
        } else {
            Ok(response_types)
        }
    }

    pub fn parse_response_type(input: &str) -> Option<Vec<ResponseType>> {
        let mut result = Vec::new();
        for word in input.split(' ') {
            let parsed_word = ResponseType::try_from(word);
            match parsed_word {
                Err(e) => {
                    debug!("{e}");
                    return None;
                }
                Ok(response_type) => result.push(response_type),
            }
        }

        Some(result)
    }
}

pub mod inject {
    use super::*;

    pub fn handler(client_store: Arc<dyn ClientStore>) -> Handler {
        Handler { client_store }
    }
}

pub mod test_fixtures {
    use super::*;
    use crate::store::test_fixtures::build_test_client_store;

    pub fn handler() -> Handler {
        inject::handler(build_test_client_store())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::oauth2::ResponseType::*;
    use crate::oidc::OidcResponseType::IdToken;
    use crate::oidc::ResponseType::*;
    use tokio::test;

    #[test]
    async fn single_response_types_are_parsed() {
        assert_eq!(
            Some(vec![OAuth2(Code)]),
            Handler::parse_response_type("code")
        );
        assert_eq!(
            Some(vec![OAuth2(Token)]),
            Handler::parse_response_type("token")
        );
        assert_eq!(
            Some(vec![Oidc(IdToken)]),
            Handler::parse_response_type("id_token")
        );
    }

    #[test]
    async fn composite_response_types_are_parsed() {
        assert_eq!(
            Some(vec![OAuth2(Code), Oidc(IdToken)]),
            Handler::parse_response_type("code id_token")
        );
        assert_eq!(
            Some(vec![OAuth2(Token), Oidc(IdToken)]),
            Handler::parse_response_type("token id_token")
        );
        assert_eq!(
            Some(vec![Oidc(IdToken), OAuth2(Token), OAuth2(Code)]),
            Handler::parse_response_type("id_token token code")
        );
    }

    #[test]
    async fn errors_are_reported() {
        assert_eq!(None, Handler::parse_response_type("code id_token invalid"));
    }
}
