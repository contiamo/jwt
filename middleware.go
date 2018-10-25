package jwt

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

type claimContextKeyType string

var (
	claimContextKey = claimContextKeyType("claims")
)

// ClaimsToContextMiddleware is a http middleware which parses and validates a jwt from the authorization header and stores the claims in the requests context before calling the next handler.
func ClaimsToContextMiddleware(handler http.Handler, header string, idpKey interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, err := GetClaimsFromRequestWithValidation(r, header, idpKey)
		if err != nil {
			http.Error(w, "not authorized: failed to validate token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := ClaimsToContext(r.Context(), claims)
		r = r.WithContext(ctx)
		handler.ServeHTTP(w, r)
	})
}

// RequireClaim checks if the requests claims contain a specific value for a specific key
func RequireClaim(handler http.Handler, claimKey, expectedClaimValue string) http.Handler {
	log := logrus.WithField("require-claim", claimKey)
	log = log.WithField("expected-value", expectedClaimValue)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			msg := "not authorized: failed to get token from context"
			log.Debug(msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
		log = log.WithField("claims", claims)
		claimVal, ok := claims[claimKey].(string)
		if !ok {
			msg := "not authorized: claim value has wrong type"
			log = log.WithField("actual-type", fmt.Sprintf("%T", claims[claimKey]))
			log.Debug(msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
		if claimVal != expectedClaimValue {
			msg := "not authorized: claim value has unexpected content"
			log = log.WithField("actual-content", claims[claimKey])
			log.Debug(msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// ClaimsFromContext retrieves the requests claims from a context
func ClaimsFromContext(ctx context.Context) Claims {
	claims, ok := ctx.Value(claimContextKey).(Claims)
	if ok {
		return claims
	}
	return nil
}

// ClaimsToContext stores claims in a context
func ClaimsToContext(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimContextKey, claims)
}
