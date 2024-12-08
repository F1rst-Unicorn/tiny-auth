# Store

Any state used by tiny-auth is held in a store. See here to determine which
store type serves you best.

|             | RAM (1) | Configuration File | LDAP simple bind | LDAP search bind | SQLite |
|-------------|---------|--------------------|------------------|------------------|--------|
| Users       | N       | Y                  | N                | Y                | Y      |
| Passwords   | N       | Y (2)              | Y                | Y                | Y      |
| Clients     | N       | Y                  | N                | Y                | Y      |
| Scopes      | N       | Y                  | N                | N                | Y      |
| Auth Codes  | Y       | N                  | N                | N                | Y      |

Notes:

1. Not persistent across restarts
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
  - ldap:
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

## Simple Bind Mode

tiny-auth binds as the `user` name passed by the user and the supplied password.

```yaml
---
store:
  - ldap:
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
  - ldap:
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

## SQLite

To activate, use the following basic configuration:

```yaml
---
store:
  - sqlite:
      name: some name
      base: /etc/tiny-auth/store.sqlite
      use for:
        scopes: true
        passwords: true
        auth codes: true
        clients: [ ]
        users:
          # 1 to 1
          - location: /user/desk
            name: desk
            multiplicity: to one
            query: |
              select
                id as tiny_auth_id, 
                occupied_by as tiny_auth_assigned_to,
                position
              from desk
              where occupied_by in ({{ tiny_auth_assigned_to }})

          # n to 1
          - location: /user/building
            name: building
            multiplicity: to one
            query: |
              select
                building.id as tiny_auth_id, 
                sits_in.user_id as tiny_auth_assigned_to,
                building.name
              from sits_in
              join building on building.id = sits_in.building_id
              where sits_in.user_id in ({{ tiny_auth_assigned_to }})

          # 1 to n
          - location: /user/pets
            name: pets
            multiplicity: to many
            query: |
              select
                pet.id as tiny_auth_id, 
                pet.name
              from pet
              where owned_by in ({{ tiny_auth_assigned_to }})
            assignment: |
              select
                pet.id as tiny_auth_id, 
                pet.owned_by as tiny_auth_assigned_to,
              where owned_by in ({{ tiny_auth_assigned_to }})

          # n to m
          - location: /building/meeting_rooms
            name: meeting_rooms
            multiplicity: to many
            query: |
              select
                meeting_room.id as tiny_auth_id,
                meeting_room.building_id as tiny_auth_assigned_to,
                meeting_room.name
              from meeting_room
              join has_access_to on meeting_room.id = has_access_to.meeting_room_id
              where has_access_to.user_id = {{ user.id }}
```

tiny-auth does not assume ownership of the database. It is perfectly fine if the
database contains other objects not managed by it. It prefixes all its objects
with `tiny_auth_`. Do not create own objects named with this prefix.
Furthermore, it is allowed to extend the `tiny_auth_user` and `tiny_auth_client`
table by more columns, again respecting the `tiny_auth_` prefix. Outside of
that prefix, tiny-auth also owns `tiny_auth_user.id`, `tiny_auth_user.name`,
`tiny_auth_user.password`, `tiny_auth_client.id`, `tiny_auth_client.client_id`,
`tiny_auth_client.client_type`, `tiny_auth_client.password`,
and `tiny_auth_client.public_key`. Do not alter these columns.

### name

An arbitrary name to reference this database. See user / client
password for details.

### base

File path to the database. It must be manually migrated to the correct version.
On upgrading, migrations to execute will be mentioned in the changelog and
packaged. The package ships with 2 migration scopes, `schema` and `reference`.
Migration files are available in `/usr/share/tiny-auth/sql/sqlite`. The schema
contains all definitions strictly required to run a sqlite store. The reference
contains scopes, clients and user columns offering features equal to what the
default store ships in `/etc/tiny-auth/store` and is optional.

### use for

Declare what data the store is responsible for. `scopes`, `passwords` and `auth 
codes` take a boolean to enable or disable them. There are no configuration
options. For `clients` and `users`, a list of data loaders can be set. A data
loader allows to add arbitrary data to a user/client context when rendering
scopes, see below. An empty list activates the store for users or clients
without any data loaders: `users: []`.

#### name

The name of a data loader identifies it when describing, how to assemble the
context. It must be unique among all data loaders of the same store. Required.

#### location

A [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901#section-3) to
where to put the data. The first element of the pointer must be a `name` of
a data loader configured _before_ the current data loader in the list, or the
predefined name `user` or `client`, depending on whether this is a user or
client data loader. Further elements will describe, how to nest the data inside
the first element via JSON objects and arrays. Required.

#### multiplicity

One of `to one` or `to many`. Controls whether the loaded data will be nested as
a JSON object or array. If a `to one` data loader loads more than one row per
assigned object, only the first row is considered. Defaults to `to many`.

#### query

The SQLite query to load the data. The result set must have an `INT` column
`tiny_auth_id` which helps tiny-auth to identify the data. It must have an `INT`
column `tiny_auth_assigned_to` which tells tiny-auth into which object the row
must be nested to. `tiny_auth_assigned_to` may be omitted, if a separate
`assignment` query is given, see below. Neither `tiny_auth_id` nor
`tiny_auth_assigned_to` will be nested into the final object. Any other columns
returned in the result set will be nested into the final object.

Queries are [tera templates](https://tera.netlify.app/docs/). To filter the
result set to only the required
rows, the variable `tiny_auth_assigned_to` contains the comma-separated list of all
IDs tiny-auth will be interested in. Note that this list can be the empty
string, which still makes SQLite IN-expressions valid syntax.
Furthermore, the `user` or `client` as well as all data loaded by other loaders
before the current one in the list are available via their name. Note that the
name can either contain an object, if the path from the client/user to the name
consists only of `to one` multiplicities, or an array otherwise. You should
name your data loaders with the correct pluralisation to reflect this.

#### assignment

An optional query to load assignments from `tiny_auth_id` to
`tiny_auth_assigned_to` data. The use case for this are queries with many result
set columns which would introduce a lot of redundant data when merging the
assignments to the other query. As with `query`, the same templating context
is provided.

## Configuration File Store

To activate, use the following basic configuration:

```yaml
---
store:
  - configuration file:
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
  ldap:
    name: my-ldap
```

`my-ldap` is the name you chose in `store.ldap.name` above.

To delegate password authentication to SQLite, use this structure:

```yaml
password:
  sqlite:
    name: my-sqlite
```

`my-sqlite` is the name you chose in `store.sqlite.name` above.

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
the [
`private_key_jwt`](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
method. The public key can be generated in the same way as the keys for
tiny-auth's [own key material](configuration.md#key-and-public-key).

The `...` is meant to be replaced by the output of tiny-auth's password
encoder (usually installed as `tiny-auth-password-encoder`). Use it to
generate a valid password for the client. The tool will output a YAML object
which must be put as a dictionary inside the `password` field. Mind the
indentation. Alternatively embed an LDAP reference, see the user password
section.

The [
`client_secret_jwt`](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
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

## Merging

It is possible to have objects split into multiple stores. E.g. user "jane" can
have some attributes stored in LDAP and others in SQLite. Objects with the same
`name` (users, scopes) or `client_id` (clients) are considered to belong to the
same object. The order of stores in the config file matters in different ways
described below, with stores listed first being stronger.

Allowed scopes and redirect URIs are formed by the union of all scopes the user
or client has listed in any store.

Scope names and descriptions are determined by the first store containing them.
Scope mappings are merged. However, you must pay attention to not have two
mappings collide on the same primitive attribute (int, string, bool, null).
Arrays and objects are merged recursively.

### Passwords

Password types are ordered as follows: Configuration File < SQLite < LDAP.
The greatest password according to that order is picked. Ties are resolved by
store order.
