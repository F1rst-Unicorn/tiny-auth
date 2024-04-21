# Store

Any state used by tiny-auth is held in a store. At the moment the only
supported store type is using configuration files. See here to determine
which store type serves you best.

|                    | OIDC | Persistence | Multiple Instances |
|--------------------|:----:|:-----------:|:------------------:|
| Configuration File |  Y   |    N (1)    |         N          |

Feature glossary:

* OIDC: Support for the entire OpenID Connect Standard
* Persistence: All state is preserved across server restarts
* Multiple Instances: Allow multiple instances of tiny-auth to collaboratively
  offer the service

Notes:

1. Authorization codes issued for the authorization code flow and the
   authentication rate limit enforcer are invalidated on restart.

## LDAP

Authentication can be delegated to LDAP. To use it for password authentication,
it first has to be declared as store here:

```yaml
---
store:
  ldap:
    name: LDAP
    bind dn format:
      - cn={{ user }},ou=users,dc=example,dc=org
    urls:
      - ldap://localhost:1389
      - ldap://localhost:1390
    connect timeout in seconds: 5
    starttls: false
```

### name

An arbitrary name to be used to reference this LDAP configuration. See user /
client password for details.

### bind dn format

A list of templates to describe how to transform the name of a user into a
distinguished name. Entries are tried in order. The only available variable is
`user` and is the string the user passes as its username.

### urls

A list of URLs tried in order to bind to the LDAP. Use the `ldap` protocol for
plain connections, `ldaps` for TLS or `ldapi` for UNIX domain sockets.

### connect timeout in seconds

Timeout for each connection attempt. After expiry, the next entry is tried.

### starttls

Enable STARTTLS on `ldap` connection.

## Configuration File Store

To activate, use the following basic configuration:

```yaml
---
store:
  configuration file:
    base: /etc/tiny-auth/store
```

Below the base directory defined in the configuration, tiny-auth expects
three directories `users/`, `clients/` and `scopes/`. All contain yaml files
where one file represents one entity, respectively.

### User Configuration

A user configuration has at least the following properties:

```yaml
---
name: johndoe
password:
  ...
allowed_scopes:
  some_client:
    - email
    - openid
```

The file must be named the same as the `name` field, appended by `.yml`.

In addition arbitrary properties may be added.

#### name

This is the primary login name used for authentication. It must be unique
between all users.

#### password

The encoded password of the user. Use tiny-auth's password encoder (usually
installed as `tiny-auth-password-encoder`) to generate a valid structure for
the user. The tool will output a YAML object which must be put as a dictionary
inside the `password` field. Mind the indentation.

To delegate password authentication to LDAP, use this structure:

```yaml
password:
  LDAP:
    name: my-ldap
```

`my-ldap` is the name you chose in `store.ldap.name` above.

#### allowed_scopes

A dictionary of clients where each client carries a list of scopes. The client
is allowed to request the following scopes without explicit consent from this
user. If the client initiates a request only consisting of allowed scopes, the
consent screen is skipped. This field is optional.

### Client Configuration

A client configuration has at least the following properties:

```yaml
client_id: relyingparty
client_type:
  confidential:
    password: ...
redirect_uris:
  - https://client.example/oidc
allowed_scopes:
  - email
```

The file must be named the same as the `client_id` field, appended by `.yml`.

In addition arbitrary properties may be added.

#### client_id

This is the name under which tiny-auth knows the client when performing
requests. It must be unique between all clients.

#### client_type

The type of the client as defined in
the [OAuth2 RFC](https://tools.ietf.org/html/rfc6749#section-2.1).

Either `client_type: public` or

```yaml
client_type:
  confidential:
    public key: <pem-key>
    password:
      ...
```

are allowed.

Confidential clients can register with a public key to support authentication
via
the [`private_key_jwt`](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
method. The public key can be generated in the same way as the keys for
tiny-auth's [own key material](configuration.md#key-and-public-key).

The `...` is meant to be replaced by the output of tiny-auth's password
encoder (usually installed as `tiny-auth-password-encoder`). Use it to
generate a valid password for the client. The tool will output a YAML object
which must be put as a dictionary inside the `password` field. Mind the
indentation. Alternatively embed an LDAP reference, see the user password
section.

The [`client_secret_jwt`](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
method is supported by tiny-auth. However, it is NOT RECOMMENDED as it requires
tiny-auth to store the client secret in plain. Note that if the client is able
to keep a secret password, it can also keep a secret key, making
`private_key_jwt` the better authentication option. If the client really
requires
this authentication method, specify the password like this:

```yaml
client_type:
  confidential:
    password:
      plain: <your client's password>
```

#### redirect_uris

The URIs to which tiny-auth is allowed to redirect to. This is defined in the
[OAuth2 RFC](https://tools.ietf.org/html/rfc6749#section-3.1.2).

#### allowed_scopes

Specify what scopes the client is allowed to request. tiny-auth will silently
drop all disallowed scopes from authorization requests. The list SHOULD at
least contain the `openid` scope.

### Scope Configuration

See the [Scopes](scopes.md) document for details.
