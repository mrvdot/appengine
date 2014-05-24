package accounts

import "net/http"

type authFunc func(http.ResponseWriter, *http.Request, *Account)

// func AuthenticatedFunc wraps a function to ensure the request is authenticated
// before passing through to the wrapped function.
// Wrapped function can be either http.HandlerFunc or authFunc (receives http.ResponseWriter, *http.Request, *Account)
func AuthenticatedFunc(fn interface{}) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		acct, err := AuthenticateRequest(req)
		if err != nil {
			if err == Unauthenticated {
				rw.WriteHeader(http.StatusUnauthorized)
			} else {
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte(err.Error()))
			}
			return
		}
		switch fn := fn.(type) {
		case authFunc:
			fn(rw, req, acct)
		case http.HandlerFunc:
			fn(rw, req)
		default:
			panic("Unsupported func passed to AuthenticatedFunc, must be authFunc or http.HandlerFunc")
		}
		ClearAuthenticatedRequest(req)
	}
}

// func AuthenicatedHandler wraps a handler and ensures everything that passes through it
// is authenticated. Useful when an entire module/subrouter should be gated by authentication
func AuthenticatedHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := AuthenticateRequest(req)
		if err != nil {
			if err == Unauthenticated {
				rw.WriteHeader(http.StatusUnauthorized)
			} else {
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte(err.Error()))
			}
			return
		}
		handler.ServeHTTP(rw, req)
		ClearAuthenticatedRequest(req)
	})
}
