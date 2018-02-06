package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	// AuthorizationHeader is the constant string used to get the Authorization
	// headers
	AuthorizationHeader = "Authorization"
)

// Claims is a map of string->something containing the meta infos associated with a token
type Claims map[string]interface{}

// CreateToken takes some claims and a private key (either rsa or ec) and returns a signed json web token
func CreateToken(claims Claims, key interface{}) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		{
			token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims(claims))
			return token.SignedString(k)
		}
	case *ecdsa.PrivateKey:
		{
			token := jwt.NewWithClaims(jwt.SigningMethodES512, jwt.MapClaims(claims))
			return token.SignedString(k)
		}
	case []byte:
		{
			token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims(claims))
			return token.SignedString(k)
		}
	}
	return "", errors.New("invalid private key")
}

// ValidateToken checks the signature of the token with a given public key and returns the associated claims
func ValidateToken(tokenString string, key interface{}) (Claims, error) {
	var (
		token *jwt.Token
		err   error
	)
	switch k := key.(type) {
	case *rsa.PublicKey:
		{
			token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return k, nil
			})
		}
	case *ecdsa.PublicKey:
		{
			token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return k, nil
			})
		}
	case []byte:
		{
			token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return k, nil
			})
		}
	}
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return Claims(claims), nil
	}
	return nil, errors.New("invalid token")
}

// GetUnvalidatedClaims extracts the token claims without validating the token
func GetUnvalidatedClaims(tokenString string) (claims Claims, err error) {

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("token contains an invalid number of segments")
	}

	claimBytes, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return nil, err
	}

	return claims, json.NewDecoder(bytes.NewBuffer(claimBytes)).Decode(&claims)
}

// LoadPublicKey loads a PEM encoded public key (either rsa or ec)
func LoadPublicKey(keyFile string) (interface{}, error) {
	bs, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(bs)
}

// ParsePublicKey parses a pem encoded public key (rsa or ecdsa based)
func ParsePublicKey(data []byte) (interface{}, error) {
	rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		ecKey, err := jwt.ParseECPublicKeyFromPEM(data)
		if err != nil {
			return nil, errors.New("unknown public key type")
		}
		return ecKey, nil
	}
	return rsaKey, nil
}

// LoadPrivateKey loads a PEM encoded private key (either rsa or ec)
func LoadPrivateKey(keyFile string) (interface{}, error) {
	bs, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(bs)
}

// ParsePrivateKey parses a pem encoded private key (rsa or ecdsa based)
func ParsePrivateKey(data []byte) (interface{}, error) {
	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		ecKey, err := jwt.ParseECPrivateKeyFromPEM(data)
		if err != nil {
			return nil, errors.New("unknown public key type")
		}
		return ecKey, nil
	}
	return rsaKey, nil
}

// GetTokenFromRequest takes the first Authorization header or `token` GET pararm , then
// extract the token prefix and json web token
func GetTokenFromRequest(r *http.Request) (prefix string, token string, err error) {

	tokenList, ok := r.Header[AuthorizationHeader]
	// pull from GET if not in the headers
	if !ok || len(tokenList) < 1 {
		tokenList, ok = r.URL.Query()["token"]
		prefix = "GET"
	}

	if len(tokenList) < 1 {
		prefix = ""
		return prefix, token, errors.New("no valid authorization header")
	}

	tokenParts := strings.Fields(tokenList[0])
	switch len(tokenParts) {
	case 1:
		token = tokenParts[0]
	case 2:
		prefix = tokenParts[0]
		token = tokenParts[1]
	default:
		return prefix, token, errors.New("invalid token: unexpected number of parts")
	}

	return prefix, token, nil
}

// GetClaimsFromRequestWithValidation extracts and validates the token from a request, returning the claims
func GetClaimsFromRequestWithValidation(r *http.Request, key interface{}) (prefix string, claims Claims, err error) {
	prefix, token, err := GetTokenFromRequest(r)
	if err != nil {
		return prefix, nil, err
	}

	claims, err = ValidateToken(token, key)
	return prefix, claims, err
}

// GetClaimsFromRequest extracts the token from a request, returning the
// claims without validating the token. This should only be used in situations
// where you can already trust or if you are simply logging the claim
// information.
func GetClaimsFromRequest(r *http.Request) (prefix string, claims Claims, err error) {
	prefix, token, err := GetTokenFromRequest(r)
	if err != nil {
		return prefix, nil, err
	}

	claims, err = GetUnvalidatedClaims(token)
	return prefix, claims, err
}
