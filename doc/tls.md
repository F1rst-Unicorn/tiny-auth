# TLS

tiny-auth support serving via TLS. If a `tls` block is specified all
requests will be served via TLS.

The configuration looks like this:

```yml
web:
  tls:
    key: path/key.pem
    certificate: path/cert.pem
    client_ca: path/ca.pem
    versions:
      - 1.2
      - 1.3
```

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

## `versions`

The list of supported TLS versions. Allowed values are `1.2` and `1.3`.