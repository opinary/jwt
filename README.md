# JWT

[![CircleCI](https://circleci.com/gh/opinary/jwt.svg?style=shield)](https://circleci.com/gh/opinary/jwt)
[![GoDoc](http://img.shields.io/badge/GoDoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/opinary/jwt)
[![License](http://img.shields.io/badge/license-Apache2-blue.svg?style=flat)](/LICENSE)


Implementation of [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
in Go.


## Examples

### Creating token

To create token that will contain your payload, you need signer instance to
create signature. This package [provides several
algorithms](https://godoc.org/github.com/opinary/jwt#Signer), but you are most
likely to use HMAC variant:

```go
const secret = `my-projects-secret-string`
signer := HMAC256([]byte(secret), "")
```

When creating token, it is allowed to define payload of any form, as long as it
can be serialized as JSON object:

```go
// define payload that will be used as JWT claims
type Payload struct {
    Email string `json:"email"`
    Admin bool   `json:"admin"`

    // JWT specific claims as defined in
    // https://tools.ietf.org/html/rfc7519#section-4.1
    ExpirationTime int64 `json:"exp"`
}

// create JWT token using given signer
token, err := Encode(signer, &Payload{
    Email:          "john.smith@example.com",
    Admin:          true,
    ExpirationTime: 2889062211,
})
if err != nil {
    fmt.Println("cannot create token:", err)
} else {
    fmt.Println("token:", string(token))
}
```

All [registered claim names](https://tools.ietf.org/html/rfc7519#section-4.1)
must be used as defined by standard and will be respected during token's
decoding.


### Decoding token and verification

To decode token's content, we must provide verifier. Because `Signer` is
implementing `Verifier` interface, we can use it for decoding as well:

```go
var payload Payload

switch err := DecodeClaims(token, signer, &payload); err {
case nil:
    fmt.Printf("payload: %v\n", payload)
case ErrExpired:
    fmt.Println("please refresh your tokne")
default:
    fmt.Println("invalid token:", err)
}
```


## More examples

See [examples section in
GoDoc](https://godoc.org/github.com/opinary/jwt#pkg-examples) to learn how to
use it.
