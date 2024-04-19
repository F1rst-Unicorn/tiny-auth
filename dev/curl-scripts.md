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

## Reflection

```bash
grpcurl \
    -key test/src/test/resources/keys/client-key.pem \
    -cert test/src/test/resources/keys/client-cert.pem \
    -cacert test/src/test/resources/keys/ca.pem \
    localhost:8089 list
grpcurl \
    -key test/src/test/resources/keys/client-key.pem \
    -cert test/src/test/resources/keys/client-cert.pem \
    -cacert test/src/test/resources/keys/ca.pem \
    localhost:8089 describe api.TinyAuthApi
```

## Change Password

```bash
grpcurl \
    -key test/src/test/resources/keys/client-key.pem \
    -cert test/src/test/resources/keys/client-cert.pem \
    -cacert test/src/test/resources/keys/ca.pem \
    -d '{"new_password": "test", "current_password": "password"}' \
    -H 'x-authorization:Bearer <access token>' \
    localhost:8089 api.TinyAuthApi/ChangePassword
```

# LDAP

```bash
docker run --rm --tty --interactive -p 1389:1389 docker.io/bitnami/openldap
ldapsearch -D cn=user01,ou=users,dc=example,dc=org -w bitnami1 -x -b dc=example,dc=org -H ldap://localhost:1389
```