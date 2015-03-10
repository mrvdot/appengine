package accounts

import "net/http"

type AuthFunc func(http.ResponseWriter, *http.Request, *Account)

// AuthenticatedFunc wraps a function to ensure the request is authenticated
// before passing through to the wrapped function.
// Wrapped function can be either http.HandlerFunc or AuthFunc (receives http.ResponseWriter, *http.Request, *Account)
// BUG - Type switch is panicking way too often right now, need to inspect
func AuthenticatedFunc(fn interface{}) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		acct, err := AuthenticateRequest(req, rw)
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
		case AuthFunc:
			fn(rw, req, acct)
		case http.HandlerFunc:
			fn(rw, req)
		default:
			panic("Unsupported func passed to AuthenticatedFunc, must be AuthFunc or http.HandlerFunc")
		}
		ClearAuthenticatedRequest(req)
	}
}

// AuthenicatedHandler wraps a handler and ensures everything that passes through it
// is authenticated. Useful when an entire module/subrouter should be gated by authentication
func AuthenticatedHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := AuthenticateRequest(req, rw)
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
