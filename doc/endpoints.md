# HTTP Endpoints

All endpoints are relative to the configured
[domain](configuration.md#domain) and [path](configuration.md#path).

## Other

### `/health`

Report health status of the system.

## OIDC Endpoints

### `/authorize`

The authorization endpoint called by OIDC RPs to get authorization from a user.

### `/userinfo`

The OIDC userinfo endpoint to get information about the authorizing user.

### `/token`

The Token endpoint to fetch a token from in the Authorization Code Flow.

### `/.well-known/openid-configuration`

The discovery endpoint for automatic discovery

### `/jwks`

The JWK Set containing the [public key](configuration.md#key-and-public-key)
used to verify tokens.
