insert into tiny_auth_authorization_code (
    client,
    user,
    redirect_uri,
    scope,
    code,
    insertion_time,
    authentication_time,
    nonce,
    pkce_challenge,
    pkce_challenge_method)
select
    tiny_auth_client.id,
    tiny_auth_user.id,
    tiny_auth_redirect_uri.id,
    ?4,
    ?5,
    ?8,
    ?6,
    ?7,
    ?9,
    ?10
from tiny_auth_client, tiny_auth_user, tiny_auth_redirect_uri
where tiny_auth_client.client_id = ?1
  and tiny_auth_user.name = ?2
  and tiny_auth_redirect_uri.client = tiny_auth_client.id
  and tiny_auth_redirect_uri.redirect_uri = ?3
