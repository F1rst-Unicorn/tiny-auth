select
    client.client_id as client,
    scope.name as scope
from user_allowed_scopes uas
         join client on uas.client = client.id
         join scope on uas.scope = scope.id
where user = ?1
