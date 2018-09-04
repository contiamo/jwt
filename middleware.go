package jwt

import "net/http"

func RequireClaim(handler http.Handler, idpKey interface{}, header, claimKey, expectedClaimValue string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, err := GetClaimsFromRequestWithValidation(r, idpKey)
		if err != nil {
			http.Error(w, "not authorized: failed to validate token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		claimVal, ok := claims[claimKey].(string)
		if !ok {
			http.Error(w, "not authorized: claim value has wrong type", http.StatusUnauthorized)
			return
		}
		if claimVal != expectedClaimValue {
			http.Error(w, "not authorized: calim value has unexpected content", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}
