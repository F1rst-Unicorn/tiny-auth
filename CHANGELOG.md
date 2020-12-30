# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Added

* HTTP health endpoint for monitoring
  ([#59](https://gitlab.com/veenj/tiny-auth/issues/59))

* System test suite mirroring [official OpenID Connect Conformance
  tests](https://www.certification.openid.net/login.html)

### Fixed

* Send error redirects via URL Fragment for token-containing response types
  ([#68](https://gitlab.com/veenj/tiny-auth/issues/68))

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
  ([#42](https://gitlab.com/veenj/tiny-auth/issues/42))

* All options in the config file can now carry spaces as word separator

### Fixed

* Handle invalid refresh tokens with correct error code
  ([#56](https://gitlab.com/veenj/tiny-auth/issues/56))

* [Rate-limit](doc/configuration.md#rate-limit) the number of failed logins per user.
  ([#35](https://gitlab.com/veenj/tiny-auth/issues/35))

## [0.7.1]

### Fixed

* Fix wrong behaviour if user has agreed to all requested scopes leading to
  showing consent screen anyway

## [0.7.0]

### Added

* Clients now need a list of allowed scopes, see
  [documentation](doc/store.md#allowed_scopes).
  ([#41](https://gitlab.com/veenj/tiny-auth/issues/41))

* Users can allow scopes to be accepted by default, skipping consent.
  ([#41](https://gitlab.com/veenj/tiny-auth/issues/41))

* Startup check for validity of all clients' redirect URIs

## [0.6.1]

## Fixed

* Allow GET requests to userinfo endpoint again

## [0.6.0]

### Added

* Allow more authentication options for the userinfo endpoint
  ([#50](https://gitlab.com/veenj/tiny-auth/issues/50))

* Allow authenticated users to return to login for a different account
  ([#47](https://gitlab.com/veenj/tiny-auth/issues/47))

### Fixed

* Report correct `auth_time` in all tokens
  ([#52](https://gitlab.com/veenj/tiny-auth/issues/52))

* Fix standard scopes. Make sure to align users supporting the `address` scope
  to the [standard
  claims!](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim)
  ([#51](https://gitlab.com/veenj/tiny-auth/issues/51))

### Security

* Bind refresh tokens to clients. It was possible for client A to obtain access
  tokens from the token endpoint by presenting a refresh token issued to a
  different client B.
  ([#54](https://gitlab.com/veenj/tiny-auth/issues/54))

## [0.5.0]

### Added

* Support for optional parameters in authorization request
  ([#19](https://gitlab.com/veenj/tiny-auth/issues/19))

### Fixed

* Respect nonce parameter of authorization requests correctly
  ([#46](https://gitlab.com/veenj/tiny-auth/issues/46))

* Fix missing kid in JWKS
  ([#45](https://gitlab.com/veenj/tiny-auth/issues/45))

## [0.4.0]

### Added

* Allow public hosting behind different port. This is a breaking change in the
  [configuration file format](doc/configuration.md#public_host)

### Fixed

* Serve correct JWKS format
  ([#43](https://gitlab.com/veenj/tiny-auth/issues/43))

## [0.3.0]

### Added

* Add [scope
  mapper](doc/scopes.md)
  support ([#10](https://gitlab.com/veenj/tiny-auth/issues/10))

### Fixed

* Fix standard compliance for confidential clients when requesting tokens
  ([#38](https://gitlab.com/veenj/tiny-auth/issues/38))

* Fix wrong URLs in discovery endpoint
  ([#39](https://gitlab.com/veenj/tiny-auth/issues/39))

### Maintenance

* Update library dependencies

## [0.2.0]

### Fixed

* Changed TLS implementation to fix reverse proxy problems. TLS configuration
  format changed, see [doc](doc/tls.md)!

### Added

* Offer refresh tokens
  ([#17](https://gitlab.com/veenj/tiny-auth/issues/17))

* Remember authenticated users
  ([#3](https://gitlab.com/veenj/tiny-auth/issues/3))

* Support password grants
  ([#9](https://gitlab.com/veenj/tiny-auth/issues/9))

* Nice UI for login forms
  ([#2](https://gitlab.com/veenj/tiny-auth/issues/2))

* [Documentation](doc/README.md)
  ([#25](https://gitlab.com/veenj/tiny-auth/issues/25))

* OpenID Connect [Discovery
  endpoint](doc/endpoints.md#well-knownopenid-configuration)
  ([#24](https://gitlab.com/veenj/tiny-auth/issues/24))

## [0.1.0]

### Added

* Support encrypted passwords
  ([#23](https://gitlab.com/veenj/tiny-auth/issues/23))

* Support client credentials authentication
  ([#8](https://gitlab.com/veenj/tiny-auth/issues/8))

* Support configuration file store
  ([#4](https://gitlab.com/veenj/tiny-auth/issues/4))

* Support for Implicit flow
  ([#7](https://gitlab.com/veenj/tiny-auth/issues/7))

* Increase HTTP Security by disabling caching and adding CSRF countermeassures
  ([#14](https://gitlab.com/veenj/tiny-auth/issues/14),
  [#1](https://gitlab.com/veenj/tiny-auth/issues/1))

* TLS support
  ([#15](https://gitlab.com/veenj/tiny-auth/issues/15))

* Issuance of access tokens
  ([#20](https://gitlab.com/veenj/tiny-auth/issues/20))

* [Archlinux](https://www.archlinux.org/) package
  ([#13](https://gitlab.com/veenj/tiny-auth/issues/13))

* Support for Authorization Code Flow
  ([#6](https://gitlab.com/veenj/tiny-auth/issues/6))
