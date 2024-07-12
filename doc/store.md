# Store

Any state used by tiny-auth is held in a store. See here to determine which
store type serves you best.

|                    | Configuration File | LDAP simple bind | LDAP search bind |
|--------------------|--------------------|------------------|------------------|
| Users              | Y                  | N                | Y                |
| Passwords          | Y (2)              | Y                | Y                |
| Clients            | Y                  | N                | Y                |
| Scopes             | Y                  | N                | N                |
| Auth Codes         | N                  | N                | N                |
| Persistence        | N (1)              | N (1)            | N (1)            |
| Multiple Instances | N (1)              | N (1)            | N (1)            |

Feature glossary:

* Persistence: All state is preserved across server restarts
* Multiple Instances: Allow multiple instances of tiny-auth to collaboratively
  offer the service

Notes:

1. Authorization codes issued for the authorization code flow and the
   authentication rate limit enforcer are invalidated on restart and not shared
   by different instances.
2. To change it, the passwords can be hashed via the Web UI. The hashed password
   must be sent to an administrator off-band. Configuration files are never
   written by tiny-auth.

## LDAP

There are two modes: simple bind and search-bind.

### General Settings

The following options are shared for both modes

```yaml
---
store:
  ldap:
    name: LDAP
    urls:
      - ldap://localhost:1389
      - ldap://localhost:1390
    connect timeout in seconds: 5
    starttls: false
```

### name

An arbitrary name to reference this LDAP configuration. See user / client
password for details.

### urls

A list of URLs tried in order to bind to the LDAP. Use the `ldap` protocol for
plain connections, `ldaps` for TLS or `ldapi` for UNIX domain sockets.

### connect timeout in seconds

Timeout for each connection attempt. After expiry, the next entry is tried.

### starttls

Enable STARTTLS on `ldap` connection.

### Simple Bind Mode

tiny-auth binds as the `user` name passed by the user and the supplied password.

```yaml
---
store:
  ldap:
    # see above for common options
    mode:
      simple bind:
        bind dn format:
          - cn={{ user }},ou=users,dc=example,dc=org
```

### bind dn format

A list of templates to describe how to transform the name of a user into a
distinguished name. Entries are tried in order until one is found. The only
available variable is `user` and is the string the user passes as its username.

## Search-Bind Mode

tiny-auth searches for the user by trying the search queries in order. On
matching of an entry, it binds as this user, supplying the password for
verification.

```yaml
---
store:
  ldap:
    # see above for common options
    mode:
      search bind:
        bind dn: "cn=tiny-auth-user,ou=users,dc=example,dc=org"
        bind dn password: "password"
        searches:
          - base dn: ou=users,dc=example,dc=org
            search filter: "(|(uid={{ user }})(mail={{ user }}))"
        use for:
          users:
            attributes:
              allowed scopes: allowed_scope
          clients:
            attributes:
              type: client_type
              redirect uri: redirect_uri
              password: password
              public key: pk
              allowed scopes: asc
```

### bind dn

The user as which the search query is run. If none is given, an anonymous bind
is attempted.

### bind dn password

The password used for binding for the search query. Omit for anonymous binding.

### searches

A list of search queries to run against the directory. The first match of the
first query is used to bind as. `base dn` is the base dn to run the query and
`search filter` is an LPAD search filter to match users. The only available
variable is `user` and is the string the user passes as its username or the
client id.

### use for

Define if this LDAP configuration is for users, clients, or both. For each of
them it is possible to define, how attributes with a meaning to tiny-auth
itself can be mapped from an LDAP.

#### User Attributes

This section is optional. If missing, the LDAP is not used for users.

##### allowed scopes

List a scope as allowed by default for a client, so if an OIDC flow only
contains allowed scopes, the consent screen is skipped. The attribute value
must be of the form `<client_id> <scope>`, e.g. `tiny-auth-frontend email`.

#### Client Attributes

This section is optional. If missing, the LDAP is not used for clients.

##### type

Either `public` or `confidential`, [see the file store](store.md#client_type).
Confidential clients are authenticated by either the `password` or the `public
key` field below. If none is specified, clients are authenticated by binding to
the LDAP.

##### redirect uri

A redirect URI allowed to be used by this client. This field is effectively
mandatory, as a client with no valid redirect URI is of limited use.

##### password

A plain-text password used for the `client_secret_jwt` client authentication
method, [see the file store](store.md#client_type). If missing, clients are
authenticated by binding to the LDAP.

##### public key

A PEM-encoded public key for `private_key_jwt` client authentication, see [the
file store](store.md#client_type). This field is optional.

##### allowed scopes

A scope name. See [the file store](store.md#allowed_scopes-1) for semantics.
This field is optional.

## Configuration File Store

To activate, use the following basic configuration:

```yaml
---
store:
  configuration file:
    name: some name
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

In addition, arbitrary properties may be added.

#### name

This is the primary login name used for authentication. It must be unique
between all users and clients.

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

In addition, arbitrary properties may be added.

#### client_id

This is the name under which tiny-auth knows the client when performing
requests. It must be unique between all clients and users.

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
