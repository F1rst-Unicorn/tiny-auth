select scope.name
from tiny_auth_client_allowed_scopes client_allowed_scopes
         join tiny_auth_scope scope on scope.id = client_allowed_scopes.scope
where client_allowed_scopes.client = ?1
