# jwt - human friendly json web token library
[![Build Status](https://travis-ci.org/Contiamo/jwt.svg?branch=master)](https://travis-ci.org/Contiamo/jwt) [![Coverage Status](https://coveralls.io/repos/github/Contiamo/jwt/badge.svg?branch=master)](https://coveralls.io/github/Contiamo/jwt?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/contiamo/jwt)](https://goreportcard.com/report/github.com/contiamo/jwt)  [![Documentation](https://godoc.org/github.com/contiamo/jwt?status.svg)](http://godoc.org/github.com/contiamo/jwt) [![GitHub issues](https://img.shields.io/github/issues/Contiamo/jwt.svg)](https://github.com/contiamo/jwt/issues)  [![Release](https://img.shields.io/github/release/Contiamo/jwt.svg?label=Release)](https://github.com/contiamo/jwt/releases)



```go
import "github.com/contiamo/jwt"
```

## Usage

#### type Claims

```go
type Claims map[string]interface{}
```

Claims is a map of string->something containing the meta infos associated with a
token

#### func CreateToken

```go
func CreateToken(claims Claims, key interface{}) (string, error)
```
CreateToken takes some claims and a key (either private rsa, private ec or hmac key) and returns a signed json web token

#### func GetTokenFromRequest

```go
func GetTokenFromRequest(r *http.Request) (string, string, error)
```
GetTokenFromRequest takes the first Authorization header and extracts the bearer
json web token

#### func LoadPrivateKey

```go
func LoadPrivateKey(keyFile string) (interface{}, error)
```
LoadPrivateKey loads a PEM encoded private key (either rsa or ec)

#### func LoadPublicKey

```go
func LoadPublicKey(keyFile string) (interface{}, error)
```
LoadPublicKey loads a PEM encoded public key (either rsa or ec)

#### func ParsePrivateKey

```go
func ParsePrivateKey(data []byte) (interface{}, error)
```
ParsePrivateKey parses a pem encoded private key (rsa or ecdsa based)

#### func ParsePublicKey

```go
func ParsePublicKey(data []byte) (interface{}, error)
```
ParsePublicKey parses a pem encoded public key (rsa or ecdsa based)

#### func GetClaimsFromRequest

```go
func GetClaimsFromRequest(r *http.Request, key interface{}) (string, Claims, error)
```
GetClaimsFromRequest extracts the token from a request, returning the claims

#### func GetClaimsFromRequestWithValidation

```go
func GetClaimsFromRequestWithValidation(r *http.Request, key interface{}) (string, Claims, error)
```
GetClaimsFromRequestWithValidation extracts and validates the token from a request, returning the claims


#### func ValidateToken

```go
func ValidateToken(tokenString string, key interface{}) (Claims, error)
```
ValidateToken checks the signature of the token with a given public key and
returns the associated claims
