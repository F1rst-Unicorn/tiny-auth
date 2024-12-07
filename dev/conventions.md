# Release

* If the release contains DB migrations, the version must be named in
  `PKGBUILD`.

Adapt the version in the following files:

* `CHANGELOG.md`
* `src/rust/Cargo.toml` and run `cargo check` to update `src/rust/Cargo.lock`
* `src/typescript/package.json`

# Tests

Always use `test_log`. Nest tokio or actix if needed. Add `rstest` if needed

# Logging rules

CID = client identifying information
This includes
* user name
* tokens

This excludes
* client IDs
* scope names

CID is logged at DEBUG at most. Passwords or password attempts are never logged.

business layer entry point logs client and username

To easily keep the log clean of CID, all CID fields have to be contained in
spans named `cid`.

log messages are all-lowercase

errors are logged with the `e` key
OIDC flow state and nonce are logged with the `flow` span.

Do not log events just to make the span entering be printed.

Do not log unauthenticated information to not suggest false certainty.