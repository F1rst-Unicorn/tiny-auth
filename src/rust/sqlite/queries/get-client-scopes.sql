select scope.name
from client_allowed_scopes
         join scope on scope.id = client_allowed_scopes.scope
where client_allowed_scopes.client = ?1
