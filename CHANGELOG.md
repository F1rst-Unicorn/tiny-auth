# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Fixed

* Changed TLS implementation to fix reverse proxy problems. TLS configuration
  format changed, see [doc](doc/tls.md)!

### Added

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
