select redirect_uri.redirect_uri
from redirect_uri
where redirect_uri.client = ?1
