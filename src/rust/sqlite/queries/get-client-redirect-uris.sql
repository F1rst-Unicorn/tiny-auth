select tiny_auth_redirect_uri.redirect_uri
from tiny_auth_redirect_uri
where tiny_auth_redirect_uri.client = ?1
