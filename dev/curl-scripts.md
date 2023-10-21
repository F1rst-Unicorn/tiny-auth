# OIDC

## Authorize

```bash
curl -c dev/cookies -Lv \
        --key test/src/test/resources/keys/client-key.pem \
        --cert test/src/test/resources/keys/client-cert.pem \
        --cacert test/src/test/resources/keys/ca.pem \
        'https://localhost:34344/authorize?client_id=tiny-auth-frontend&state=state&nonce=nonce&scope=openid%20profile&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A34344'
```

## Token

### Password based

```bash
curl --request POST \
        --key test/src/test/resources/keys/client-key.pem \
        --cert test/src/test/resources/keys/client-cert.pem \
        --cacert test/src/test/resources/keys/ca.pem \
        -H 'content-type: application/x-www-form-urlencoded' \
        --data 'grant_type=password&username=john&password=password&client_id=confidential&client_secret=password' \
        'https://localhost:34344/token'
```

# GRPC

## Change Password

```bash
grpc_cli call localhost:8089 api.TinyAuthApi.ChangePassword \
        "new_password: 'test', current_password: 'password'" \
        --proto_path=src/proto/ \
        --metadata 'x-authorization:Bearer <access token>'
```