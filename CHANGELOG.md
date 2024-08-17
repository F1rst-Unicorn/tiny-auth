# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Added

* Store files are now watched for changes and reload their content automatically
  without server restart
  ([#102](https://j.njsm.de/git/veenj/tiny-auth/issues/102)).

* Scope claims can now go to only some of access token, id token or userinfo
  ([#76](https://j.njsm.de/git/veenj/tiny-auth/issues/76)).

### Fixed

* Validate token audience for own API
  ([#103](https://j.njsm.de/git/veenj/tiny-auth/issues/103)).

* Configuration reloading now also works with vim.

## [2.0.0]

### Added

Configuration option to configure shutdown timeout in `web.shutdown timeout in
seconds` ([#99](https://j.njsm.de/git/veenj/tiny-auth/issues/99)).

Support a new store via LDAP. See [doc](doc/store.md) for
configuration. It allows to store users, clients and their passwords inside
LDAP instead of tiny-auth
itself ([#48](https://j.njsm.de/git/veenj/tiny-auth/issues/48)).

The health endpoint checks all LDAPs for
connectivity ([#94](https://j.njsm.de/git/veenj/tiny-auth/issues/94)).

**Breaking**: The store is now a list and each entry needs a
name. Pick any name that lets you easily distinguish your stores. It will be
used in logs and user/client passwords. Change your store from

```yaml
store:
  configuration file:
    base: /etc/tiny-auth/store
```

to

```yaml
store:
  - configuration file:
      name: configuration file
      base: /etc/tiny-auth/store
```

The log format is now embedded in the main configuration file, too. Consider
the [relevant subsection](doc/configuration.md#log) as the new config is
not fully compatible with the old one.

### Changed

Logging is now done with the `tracing` framework. This allows getting deeper
insight into application
execution ([#86](https://j.njsm.de/git/veenj/tiny-auth/issues/86)).

### Fixed

* tiny-auth-frontend now uses `nonce` values in OIDC flow.

## [1.0.1]

### Fixed

* Allow proper deployment on public domain which is different from the own
  hostname.

* Indent password result on changing password properly.

## [1.0.0]

### Added

* Web UI to change passwords
  ([#57](https://j.njsm.de/git/veenj/tiny-auth/issues/57)).

* Support to run under MacOS
  ([#79](https://j.njsm.de/git/veenj/tiny-auth/issues/79)).

* Support for [PKCE](https://www.rfc-editor.org/rfc/rfc7636)
  ([#75](https://j.njsm.de/git/veenj/tiny-auth/issues/75)).

* Support rotation of token signing keys
  ([#55](https://j.njsm.de/git/veenj/tiny-auth/issues/55)). See documentation
  section `crypto` configuration.

* Allow configuration of the cookie's `SameSite` attribute via configuration
  option `web.session same site policy`.

* Allow configuration of token timeouts via `web.token timeout in seconds` and
  `web.refresh token timeout in seconds`
  ([#78](https://j.njsm.de/git/veenj/tiny-auth/issues/78)).

### Fixed

* Fix panic when authorising a request with unknown scope
  ([#72](https://j.njsm.de/git/veenj/tiny-auth/issues/72))

* Fix key-independent key ID (`kid`) in JWKS when using ECDSA keys.

### Deprecated

* `web.session timeout` was replaced in favour of `web.session timeout in
  seconds`.

* `crypto.key` and `crypto.public key` were replaced in favour of a list of such
  keys
  ([#55](https://j.njsm.de/git/veenj/tiny-auth/issues/75)).

### Maintenance

* Fix linter issues

* Due to a change in the cookie storage format, all sessions are invalidated.

## [0.8.2]

### Added

* HTTP health endpoint for monitoring
  ([#59](https://j.njsm.de/git/veenj/tiny-auth/issues/59))

* System test suite mirroring [official OpenID Connect Conformance
  tests](https://www.certification.openid.net/login.html)

### Fixed

* Send error redirects via URL Fragment for token-containing response types
  ([#68](https://j.njsm.de/git/veenj/tiny-auth/issues/68))

* Refresh tokens issued for different clients now return the correct HTTP
  response code.

* Prevent clients from requesting scopes which they are not allowed via client
  credentials or password grant.

## [0.8.1]

### Maintenance

* Update library dependencies

## [0.8.0]

### Added

* Support all client authentication methods
  ([#42](https://j.njsm.de/git/veenj/tiny-auth/issues/42))

* All options in the config file can now carry spaces as word separator

### Fixed

* Handle invalid refresh tokens with correct error code
  ([#56](https://j.njsm.de/git/veenj/tiny-auth/issues/56))

* [Rate-limit](doc/configuration.md#rate-limit) the number of failed logins per
  user.
  ([#35](https://j.njsm.de/git/veenj/tiny-auth/issues/35))

## [0.7.1]

### Fixed

* Fix wrong behaviour if user has agreed to all requested scopes leading to
  showing consent screen anyway

## [0.7.0]

### Added

* Clients now need a list of allowed scopes, see
  [documentation](doc/store.md#allowed_scopes).
  ([#41](https://j.njsm.de/git/veenj/tiny-auth/issues/41))

* Users can allow scopes to be accepted by default, skipping consent.
  ([#41](https://j.njsm.de/git/veenj/tiny-auth/issues/41))

* Startup check for validity of all clients' redirect URIs

## [0.6.1]

## Fixed

* Allow GET requests to userinfo endpoint again

## [0.6.0]

### Added

* Allow more authentication options for the userinfo endpoint
  ([#50](https://j.njsm.de/git/veenj/tiny-auth/issues/50))

* Allow authenticated users to return to login for a different account
  ([#47](https://j.njsm.de/git/veenj/tiny-auth/issues/47))

### Fixed

* Report correct `auth_time` in all tokens
  ([#52](https://j.njsm.de/git/veenj/tiny-auth/issues/52))

* Fix standard scopes. Make sure to align users supporting the `address` scope
  to the [standard
  claims!](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim)
  ([#51](https://j.njsm.de/git/veenj/tiny-auth/issues/51))

### Security

* Bind refresh tokens to clients. It was possible for client A to obtain access
  tokens from the token endpoint by presenting a refresh token issued to a
  different client B.
  ([#54](https://j.njsm.de/git/veenj/tiny-auth/issues/54))

## [0.5.0]

### Added

* Support for optional parameters in authorization request
  ([#19](https://j.njsm.de/git/veenj/tiny-auth/issues/19))

### Fixed

* Respect nonce parameter of authorization requests correctly
  ([#46](https://j.njsm.de/git/veenj/tiny-auth/issues/46))

* Fix missing kid in JWKS
  ([#45](https://j.njsm.de/git/veenj/tiny-auth/issues/45))

## [0.4.0]

### Added

* Allow public hosting behind different port. This is a breaking change in the
  [configuration file format](doc/configuration.md#public_host)

### Fixed

* Serve correct JWKS format
  ([#43](https://j.njsm.de/git/veenj/tiny-auth/issues/43))

## [0.3.0]

### Added

* Add [scope
  mapper](doc/scopes.md)
  support ([#10](https://j.njsm.de/git/veenj/tiny-auth/issues/10))

### Fixed

* Fix standard compliance for confidential clients when requesting tokens
  ([#38](https://j.njsm.de/git/veenj/tiny-auth/issues/38))

* Fix wrong URLs in discovery endpoint
  ([#39](https://j.njsm.de/git/veenj/tiny-auth/issues/39))

### Maintenance

* Update library dependencies

## [0.2.0]

### Fixed

* Changed TLS implementation to fix reverse proxy problems. TLS configuration
  format changed, see [doc](doc/tls.md)!

### Added

* Offer refresh tokens
  ([#17](https://j.njsm.de/git/veenj/tiny-auth/issues/17))

* Remember authenticated users
  ([#3](https://j.njsm.de/git/veenj/tiny-auth/issues/3))

* Support password grants
  ([#9](https://j.njsm.de/git/veenj/tiny-auth/issues/9))

* Nice UI for login forms
  ([#2](https://j.njsm.de/git/veenj/tiny-auth/issues/2))

* [Documentation](doc/README.md)
  ([#25](https://j.njsm.de/git/veenj/tiny-auth/issues/25))

* OpenID Connect [Discovery
  endpoint](doc/endpoints.md#well-knownopenid-configuration)
  ([#24](https://j.njsm.de/git/veenj/tiny-auth/issues/24))

## [0.1.0]

### Added

* Support encrypted passwords
  ([#23](https://j.njsm.de/git/veenj/tiny-auth/issues/23))

* Support client credentials authentication
  ([#8](https://j.njsm.de/git/veenj/tiny-auth/issues/8))

* Support configuration file store
  ([#4](https://j.njsm.de/git/veenj/tiny-auth/issues/4))

* Support for Implicit flow
  ([#7](https://j.njsm.de/git/veenj/tiny-auth/issues/7))

* Increase HTTP Security by disabling caching and adding CSRF countermeassures
  ([#14](https://j.njsm.de/git/veenj/tiny-auth/issues/14),
  [#1](https://j.njsm.de/git/veenj/tiny-auth/issues/1))

* TLS support
  ([#15](https://j.njsm.de/git/veenj/tiny-auth/issues/15))

* Issuance of access tokens
  ([#20](https://j.njsm.de/git/veenj/tiny-auth/issues/20))

* [Archlinux](https://www.archlinux.org/) package
  ([#13](https://j.njsm.de/git/veenj/tiny-auth/issues/13))

* Support for Authorization Code Flow
  ([#6](https://j.njsm.de/git/veenj/tiny-auth/issues/6))
