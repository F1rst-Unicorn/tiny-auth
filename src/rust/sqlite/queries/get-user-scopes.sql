select
    client.client_id as client,
    scope.name as scope
from tiny_auth_user_allowed_scopes uas
         join tiny_auth_client client on uas.client = client.id
         join tiny_auth_scope scope on uas.scope = scope.id
where user = ?1
