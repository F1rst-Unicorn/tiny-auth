select
    c.id,
    redirect_uri.redirect_uri,
    c.insertion_time,
    user.name,
    c.scope,
    c.authentication_time,
    c.nonce,
    c.pkce_challenge,
    c.pkce_challenge_method
from authorization_code c
         join user on user.id = c.user
         join redirect_uri on redirect_uri.id = c.redirect_uri
where c.code = ?1
  and c.client = (
    select client.id
    from client
    where client.client_id = ?2
    )
