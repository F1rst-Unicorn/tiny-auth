#!/usr/bin/env bash

if [ -z "$NEXTEST_ENV" ]; then
    exit 1
fi

echo RUST_LOG=$(echo 'warn,
    tiny_auth_main=trace,
    tiny_auth_web=trace,
    tiny_auth_business=trace,
    tiny_auth_api=trace,
    tiny_auth_ldap=trace,
    tiny_auth=trace,
    [cid]=trace,
    tiny_auth_main::config::parser=debug,
    tiny_auth_main::systemd::linux=debug,
    tiny_auth_business::store::memory=debug,
    tiny_auth_sqlite=trace,
    log=info,
    sqlx::query=trace' | sed -z "s/\n//g; s/, */,/g") >> "$NEXTEST_ENV"
echo RUST_BACKTRACE=1 >> "$NEXTEST_ENV"
# no span events by default, see https://github.com/d-e-s-o/test-log?tab=readme-ov-file#logging-configuration
echo RUST_LOG_SPAN_EVENTS= >> "$NEXTEST_ENV"
