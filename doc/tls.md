# TLS

tiny-auth support serving via TLS. If a `tls` block is specified all
requests will be served via TLS.

The configuration looks like this:

```yml
web:
  tls:
    configuration: modern v5
    key: path/key.pem
    certificate: path/cert.pem
    client_ca: path/ca.pem
    dh_param: path/dhparam.pem
    1.2 ciphers: HIGH
    1.3 cipers: HIGH
```

## `configuration`

Supported values are

* `modern`

* `modern v5`

* `intermediate`

* `intermediate v5`

They correspond to [Mozilla's TLS Recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS).

## `key`

The file path to a PEM-formatted private key.

## `certificate`

The file path to a certificate chain. The file should contain a sequence
of PEM-formatted certificates, the first being the leaf certificate, and
the remainder forming the chain of certificates up to and including the
trusted root certificate.

## `client_ca`

The file path to a list of PEM-formatted certificates. They will be used
to verify client requests. If specified all client requests need to be
authenticated. The maximum verification depth is 30.

Omitting this parameter will turn off client certificate verification.

## `dh_param`

The Diffie-Hellman parameters to use. See `man 1 dhparam`. The use is
optional.

## `1.2 ciphers` and `1.3 ciphers`

The ciphers to be used by openssl. See `man 1 ciphers` for details on
the format. Their use is optional.
