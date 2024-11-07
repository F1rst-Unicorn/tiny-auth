select
    c.id,
    r.redirect_uri,
    c.insertion_time,
    u.name,
    c.scope,
    c.authentication_time,
    c.nonce,
    c.pkce_challenge,
    c.pkce_challenge_method
from tiny_auth_authorization_code c
         join tiny_auth_user u on u.id = c.user
         join tiny_auth_redirect_uri r on r.id = c.redirect_uri
where c.code = ?1
  and c.client = (
    select client.id
    from tiny_auth_client client
    where client.client_id = ?2
    )
