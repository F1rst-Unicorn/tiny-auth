select
    c.id,
    c.redirect_uri,
    c.insertion_time,
    c.user,
    c.scope,
    c.authentication_time,
    c.nonce,
    c.pkce_challenge,
    c.pkce_challenge_method
from tiny_auth_authorization_code c
where c.code = ?1
and c.client_id =  ?2
