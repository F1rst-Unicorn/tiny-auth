# Store

Any state used by tiny-auth is held in a store. At the moment the only
supported store type is using configuration files. See here to determine
which store type serves you best.

|                    | OIDC | Persistence | Multiple Instances |
|--------------------|:----:|:-----------:|:------------------:|
| Configuration File | Y    | N (1)       | N                  |

Feature glossary:

* OIDC: Support for the entire OpenID Connect Standard
* Persistence: All state is preserved across server restarts
* Multiple Instances: Allow multiple instances of tiny-auth to collaboratively
  offer the service

Notes:

1. Authorization codes issued for the authorization code flow are invalidated
   on restart.

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

### Client Configuration

A client configuration has at least the following properties:

```yaml
client_id: relyingparty
client_type:
  confidential:
    password: password
redirect_uris:
  - https://client.example/oidc
```

The file must be named the same as the `client_id` field, appended by `.yml`.

In addition arbitrary properties may be added.

#### client_id

This is the name under which tiny-auth knows the client when performing
requests. It must be unique between all clients.

#### client_type

The type of the client as defined in the [OAuth2 RFC](https://tools.ietf.org/html/rfc6749#section-2.1).

Either `client_type: public` or

```yaml
client_type:
  confidential:
    password:
      ...
```

are allowed.

The `...` is meant to be replaced by the output of tiny-auth's password
encoder (usually installed as `tiny-auth-password-encoder`). Use it to
generate a valid password for the client. The tool will output a YAML object
which must be put as a dictionary inside the `password` field. Mind the
indentation.

#### redirect_uris

The URIs to which tiny-auth is allowed to redirect to. This is defined in the
[OAuth2 RFC](https://tools.ietf.org/html/rfc6749#section-3.1.2).

### Scope Configuration

See the [Scopes](scopes.md) document for details.