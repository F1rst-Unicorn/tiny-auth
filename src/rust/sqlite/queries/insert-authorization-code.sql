insert into authorization_code (
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
    client.id,
    user.id,
    redirect_uri.id,
    ?4,
    ?5,
    ?8,
    ?6,
    ?7,
    ?9,
    ?10
from client, user, redirect_uri
where client.client_id = ?1
  and user.name = ?2
  and redirect_uri.client = client.id
  and redirect_uri.redirect_uri = ?3