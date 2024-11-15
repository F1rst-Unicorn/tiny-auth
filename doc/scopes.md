# Scopes

OpenID Connect allows clients to request claims into the token based on so
called scopes. Here your learn how to configure your custom scopes to adapt
tiny-auth's token claim generation to your needs.

## Configuration format

The scope itself requires some basic properties to be set.

```yaml
---
name: Technical name for usage in HTTP requests
pretty name: A human-friendly name presented on the consent webpage
description: A human-friendly description of what the user agrees to release

mappings: [ ]
```

The file has to carry the name stated inside the file with the `.yml`
extension.

For SQLite stores, this corresponds to the table `tiny_auth_scope`.

### Scope Mappings

A scope mapping defines how existing information is transformed into a JWT
claim inside the ID Token. tiny-auth ships with pre-configured scope files
for the well-known [OpenID Connect
scopes](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims).

A trivial mapping looks like this:

```yaml
---
structure:
  my_claim: hello world
type: plain
optional: false
destination:
  - access token
```

For SQLite stores, this corresponds to the table `tiny_auth_scope_mapping`.

This will map the plain YAML object below `structure` into the token. Every
mapping has a `structure` which defines the structure of the object put into
the token. For SQLite stores, see in the types sections below.

The compulsory `type` defines the behaviour of the mapping (see below for all
types).

`destination` controls, where the mapping should be visible. It takes a list of
any of these values: `access token`, `id token`, `userinfo`. The default is to
include it in all destinations. Most claims should only have destination
`userinfo`. Tokens are used for authentication via HTTP headers for which most
servers have size limitations. To avoid having tokens rejected because of their
size, only the minimal needed information should be included in the tokens.
For SQLite stores, these correspond to the three boolean `destination_*`
flags.

`optional` is an optional flag defaulting to `false`. Since claim generation
may fail due to configuration errors, there are two behaviours: Claims coming
from optional mappings are silently dropped from the token on failure while
other mappings in the same token will be present. If the mapping is not
optional and it fails to generate claims, the whole scope is considered
malformed and no claims will be added from it.

When writing your own scopes, the tool `tiny-auth-scope-debugger` can help
you to test the scope. Make sure to set `optional: false` during testing to
catch all errors.

Below you find the description of the mapping types.

#### Plain

A `plain` mapping hardcodes whatever claims it finds below the `structure`
field into all tokens.

For SQLite stores, put the settings specific to `plain` into a
`tiny_auth_scope_mapping_plain` row.
The `structure` is
a [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901#section-3),
describing where to put the value.
As the value will be put into a JSON object (user or client) at least one token
must be given and will be interpreted as an object field.
The `type` is one of `null`, `string`, `number`, `boolean` describing how the
`value` will be mapped to JSON.

#### Template

A `template` mapping allows writing string templates with the [tera template
engine](https://tera.netlify.app/docs/). Read the documentation of tera for a
full feature list of it. Also examples are provided in the pre-configured
scopes `email` and `profile`.

Inside the templates you can access the following variables:

| Name     | Description                                                                                                |
|:---------|:-----------------------------------------------------------------------------------------------------------|
| `user`   | The user currently authenticating. You can access any attribute set for the current user                   |
| `client` | The OpenID Connect Client initiating the protocol. You can access any attribute set for the current client |

#### User / Client attribute

A `user_attribute` or `client_attribute` can be used to copy arbitrary parts
of the user/client object into the token. It is best outlined with an
example:

##### User

```yaml
---
name: john
password: ...

access:
  building1:
    - front door
    - emergency exit
  building2:
    - emergency exit
```

##### Scope

```yaml
---
name: scope
pretty name: scope
description: scope
mappings:
  - type:
      user_attribute:
        access: null
    structure:
      building_access: null
```

Analogously in a SQLite store, the `user_attribute` or `client_attribute` is a
[JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901#section-3) to the
attribute to select. In the example `/access`.
Similarly, the `structure` pointer is `/building_access`.

The ID Token will then contain the following claim:

```json
{
  "building_access": {
    "access": {
      "building1": [
        "front door",
        "emergency exit"
      ],
      "building2": [
        "emergency exit"
      ]
    }
  }
}
```

Formally it takes the subobject rooted at the `user_attribute` path ending in
`null`, copies it into the `structure` at the `null` mark and puts the
resulting structure into the token.
