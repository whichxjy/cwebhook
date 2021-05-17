# Cwebhook

**Cwebhook** is a library for generating and validating Webhook digital signatures.

## Usage

Generating digital signature:

```go
signature, err := cwebhook.CreateSignature(timestamp, payload, secret, cwebhook.HashAlgoSha256)
```

Validating digital signature:

```go
err := cwebhook.Validate(signature, timestamp, payload, secret)
```
