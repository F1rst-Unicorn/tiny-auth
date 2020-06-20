# HTTP Endpoints

All endpoints are relative to the configured
[domain](doc/configuration.md#domain) and [path](doc/configuration.md#path).

## OIDC Endpoints

### `/authorize`

The authorization endpoint called by OIDC RPs to get authorization from a user.

### `/userinfo`

The OIDC userinfo endpoint to get information about the authorizing user.

### `/token`

The Token endpoint to fetch a token from in the Authorization Code Flow.

## Custom endpoints

### `/cert`

The [public key](doc/configuration.md#key-and-public-key) used to verify JWT
tokens from this instance.
