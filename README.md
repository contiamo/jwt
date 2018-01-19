# jwt - human friendly json web token library

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

#### func  CreateToken

```go
func CreateToken(claims Claims, key interface{}) (string, error)
```
CreateToken takes some claims and a private key (either rsa or ec) and returns a
signed json web token

#### func  GetTokenFromRequest

```go
func GetTokenFromRequest(r *http.Request) (string, error)
```
GetTokenFromRequest takes the first Authorization header and extracts the bearer
json web token

#### func  LoadPrivateKey

```go
func LoadPrivateKey(keyFile string) (interface{}, error)
```
LoadPrivateKey loads a PEM encoded private key (either rsa or ec)

#### func  LoadPublicKey

```go
func LoadPublicKey(keyFile string) (interface{}, error)
```
LoadPublicKey loads a PEM encoded public key (either rsa or ec)

#### func  ParsePrivateKey

```go
func ParsePrivateKey(data []byte) (interface{}, error)
```
ParsePrivateKey parses a pem encoded private key (rsa or ecdsa based)

#### func  ParsePublicKey

```go
func ParsePublicKey(data []byte) (interface{}, error)
```
ParsePublicKey parses a pem encoded public key (rsa or ecdsa based)

#### func  GetClaimsFromRequest

```go
func GetClaimsFromRequest(r *http.Request, key interface{}) (Claims, error)
```
GetClaimsFromRequest extracts the

#### func  ValidateToken

```go
func ValidateToken(tokenString string, key interface{}) (Claims, error)
```
ValidateToken checks the signature of the token with a given public key and
returns the associated claims
