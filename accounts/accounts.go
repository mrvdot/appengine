//Package account handles all authentication and
//account scoping for tests/decisions/calculations
package accounts

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"time"

	"appengine"
	"appengine/datastore"
	"appengine/memcache"
)

// func AuthenticateRequest takes an http.Request and validates it against existing accounts and sessions
// Checks first for an account slug, then falls back on acct session key if slug is not present
// Returns an account (if valid) or error if unable to find acct matching account
func AuthenticateRequest(req *http.Request) (*Account, error) {
	ctx := appengine.NewContext(req)
	slug := req.Header.Get(Headers["account"])
	if slug == "" {
		sessionKey := req.Header.Get(Headers["session"])
		acct, _, err := authenticateSession(ctx, sessionKey)
		if err != nil {
			return nil, err
		}
		return acct, nil
	}
	apiKey := req.Header.Get(Headers["key"])
	return authenticateAccount(ctx, slug, apiKey)
}

// func authenticateAccount takes acct accountId and key, authenticates it,
// returning acct session if valid, or error if invalid
// Also stores valid within authenticatedAccounts for later retrieval via authenticateSessions
func authenticateAccount(ctx appengine.Context, accountSlug, accountKey string) (*Account, error) {
	acct, err := getAccountFromSlug(ctx, accountSlug, accountKey)
	if err != nil {
		return nil, err
	}

	_, err = createSession(ctx, acct)
	if err != nil {
		// If we fail to create session, log it, but don't completely bail on authenticating account
		ctx.Warningf("Error creating session for account: %v", err.Error())
	}
	return acct, nil
}

// func authenticateSession takes acct session key and validates it
func authenticateSession(ctx appengine.Context, sessionKey string) (acct *Account, session *Session, err error) {
	session, err = getSession(ctx, sessionKey)
	if err != nil {
		return nil, nil, Unauthenticated
	}
	acct, err = getAccountFromSession(ctx, session)
	if err != nil {
		return nil, nil, Unauthenticated
	}
	now := time.Now()
	if now.After(session.LastUsed.Add(session.TTL)) {
		return nil, nil, SessionExpired
	}
	session.LastUsed = now
	storeAuthenticatedRequest(ctx, acct, session)
	return acct, session, nil
}

// func GetAccount returns the currently authenticated account, or an error if no account
// has been authenticated for this request
func GetAccount(ctx appengine.Context) (*Account, error) {
	reqId := appengine.RequestID(ctx)
	if acct, ok := authenticatedAccounts[reqId]; ok {
		return acct, nil
	}
	return nil, Unauthenticated
}

// func GetAccountKey returns the datastore key for the current account, or an error if no account
// has been authenticated for this request
func GetAccountKey(ctx appengine.Context) (*datastore.Key, error) {
	acct, err := GetAccount(ctx)
	if err != nil {
		return nil, err
	}
	return acct.GetKey(ctx), nil
}

// func GetSession takes an appengine.Context and returns the appropriate session
func GetSession(ctx appengine.Context) (session *Session, err error) {
	reqId := appengine.RequestID(ctx)
	session, ok := authenticatedSessions[reqId]
	if ok {
		return
	}
	return nil, Unauthenticated
}

// func GetContext returns acct namespaced context for the currently authenticated account
// Useful for multi-tenant applications
func GetContext(req *http.Request) (appengine.Context, error) {
	ctx := appengine.NewContext(req)
	//acctKey, err := GetAccountKey(ctx)
	acct, err := GetAccount(ctx)
	if err != nil {
		if err != Unauthenticated {
			ctx.Errorf("[accounts/GetContext] %v", err.Error())
		}
		return nil, err
	}
	return appengine.Namespace(ctx, acct.Slug)
}

func getSession(ctx appengine.Context, key string) (*Session, error) {
	if session, ok := sessions[key]; ok {
		return session, nil
	}
	session := &Session{}
	_, err := memcache.Gob.Get(ctx, "session-"+key, session)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func storeSession(ctx appengine.Context, session *Session, acct *Account) {
	key := session.Key
	sessions[key] = session
	sessionToAccount[session] = acct
	i := &memcache.Item{
		Key:    "session-" + session.Key,
		Object: session,
	}
	err := memcache.Gob.Set(ctx, i)
	if err != nil {
		ctx.Errorf(err.Error())
	}
}

func createSession(ctx appengine.Context, acct *Account) (*Session, error) {
	now := time.Now()
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%v-%d", acct.Slug, now.UnixNano()))
	hash := h.Sum(nil)
	acctKey := acct.GetKey(ctx)
	session := &Session{
		Key:         fmt.Sprintf("%x", hash),
		Account:     acctKey,
		Initialized: now,
		LastUsed:    now,
		TTL:         SessionTTL,
	}
	storeSession(ctx, session, acct)
	storeAuthenticatedRequest(ctx, acct, session)
	return session, nil
}

func storeAuthenticatedRequest(ctx appengine.Context, acct *Account, session *Session) {
	reqId := appengine.RequestID(ctx)
	authenticatedAccounts[reqId] = acct
	authenticatedSessions[reqId] = session
}

// func ClearAuthenticatedRequest removes a request from the internal authentication mappings to both account and session
// called automatically after a request has been processed by AuthenticatedHandler and AuthenticatedFunc
func ClearAuthenticatedRequest(req *http.Request) {
	ctx := appengine.NewContext(req)
	reqId := appengine.RequestID(ctx)
	delete(authenticatedAccounts, reqId)
	delete(authenticatedSessions, reqId)
}

func getAccountFromSession(ctx appengine.Context, session *Session) (*Account, error) {
	if acct, ok := sessionToAccount[session]; ok {
		return acct, nil
	}
	acctKey := session.Account
	acct := &Account{}
	err := datastore.Get(ctx, acctKey, acct)
	if err != nil {
		return nil, NoSuchSession
	}
	acct.Load(ctx)
	return acct, nil
}

func getAccountFromSlug(ctx appengine.Context, slug string, apiKey string) (*Account, error) {
	iter := datastore.NewQuery("Account").
		Filter("Slug = ", slug).
		Limit(1).
		Run(ctx)

	acct := &Account{}
	_, err := iter.Next(acct)
	if err != nil {
		return nil, NoSuchAccount
	}
	if acct.ApiKey != apiKey {
		return nil, InvalidApiKey
	}
	acct.Load(ctx)
	return acct, nil
}
