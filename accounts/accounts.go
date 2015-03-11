// Package account handles the authentication and
// account creation flow for APIs
package accounts

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrvdot/appengine/aeutils"
	"github.com/qedus/nds"

	"appengine"
	"appengine/datastore"
	"appengine/memcache"
)

var (
	mockAccount *Account
)

// Mock the currently authenticated account
// Useful for testing and debugging
func MockAccount(acct *Account) {
	mockAccount = acct
}

// AuthenticateRequest takes an http.Request and validates it against existing accounts and sessions
// Checks first for an account slug, then falls back on acct session key if slug is not present
// Returns an account (if valid) or error if unable to find acct matching account
func AuthenticateRequest(req *http.Request, rw http.ResponseWriter) (acct *Account, err error) {
	if mockAccount != nil {
		return mockAccount, nil
	}
	ctx := appengine.NewContext(req)

	if slug := req.Header.Get(Headers["account"]); slug != "" {
		apiKey := req.Header.Get(Headers["key"])
		acct, err = authenticateAccount(ctx, slug, apiKey)
		if err == nil {
			session, _ := GetSession(ctx)
			sendSession(req, rw, session)
		}
		return
	} else if username := req.Header.Get(Headers["slug"]); username != "" {
		password := req.Header.Get(Headers["password"])
		acct, err = authenticateAccountByUser(ctx, username, password)
		if err == nil {
			session, _ := GetSession(ctx)
			sendSession(req, rw, session)
		}
		return
	} else {
		sessionKey := sessionKeyFromRequest(req)
		if sessionKey == "" {
			return nil, Unauthenticated
		}
		acct, _, err := authenticateSession(ctx, sessionKey)
		if err != nil {
			return nil, err
		}
		return acct, nil
	}
}

// authenticateAccount takes acct accountId and key, authenticates it,
// returning acct session if valid, or error if invalid
// Also stores valid within authenticatedAccounts for later retrieval via authenticateSessions
func authenticateAccount(ctx appengine.Context, accountSlug, accountKey string) (*Account, error) {
	acct, err := getAccountFromSlug(ctx, accountSlug, accountKey)
	if err != nil {
		return nil, err
	}

	_, err = createSession(ctx, acct, nil)
	if err != nil {
		// If we fail to create session, log it, but don't completely bail on authenticating account
		ctx.Warningf("Error creating session for account: %v", err.Error())
	}
	return acct, nil
}

// authenticateAccountByUser looks for a user account matching username and password
// and if finds it, logs in the related account and returns it
func authenticateAccountByUser(ctx appengine.Context, username, password string) (*Account, error) {
	user, err := AuthenticateUser(ctx, username, password)
	if err != nil {
		return nil, err
	}

	acct := user.Account(ctx)
	if acct == nil {
		return nil, errors.New("Orphaned user object has no account")
	}

	_, err = createSession(ctx, acct, user)
	if err != nil {
		// If we fail to create session, log it, but don't completely bail on authenticating account
		ctx.Warningf("Error creating session for account: %v", err.Error())
	}
	return acct, nil
}

// authenticateSession takes account session key and validates it
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
	storeAuthenticatedRequest(ctx, acct, session, nil)
	return acct, session, nil
}

// Get Session key from request, checking Headers first, then Cookies
func sessionKeyFromRequest(req *http.Request) (sessionKey string) {
	headerName := Headers["session"]
	sessionKey = req.Header.Get(headerName)
	if sessionKey == "" {
		// fall back on cookie if we can
		sessionCookie, err := req.Cookie(headerName)
		if err != nil {
			return
		}
		sessionKey = sessionCookie.Value
	}
	return
}

// GetAccount returns the currently authenticated account, or an error if no account
// has been authenticated for this request
func GetAccount(ctx appengine.Context) (*Account, error) {
	if mockAccount != nil {
		return mockAccount, nil
	}
	reqId := appengine.RequestID(ctx)
	if acct, ok := authenticatedAccounts[reqId]; ok {
		return acct, nil
	}
	return nil, Unauthenticated
}

func GetUser(ctx appengine.Context) (*User, error) {
	reqId := appengine.RequestID(ctx)
	if user, ok := authenticatedUsers[reqId]; ok {
		return user, nil
	}
	return nil, Unauthenticated
}

// GetAccountKey returns the datastore key for the current account, or an error if no account
// has been authenticated for this request
func GetAccountKey(ctx appengine.Context) (*datastore.Key, error) {
	acct, err := GetAccount(ctx)
	if err != nil {
		return nil, err
	}
	return acct.GetKey(ctx), nil
}

// GetSession takes an appengine.Context and returns the appropriate session
func GetSession(ctx appengine.Context) (session *Session, err error) {
	reqId := appengine.RequestID(ctx)
	session, ok := authenticatedSessions[reqId]
	if ok {
		return
	}
	return nil, Unauthenticated
}

// GetContext returns acct namespaced context for the currently authenticated account
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

func storeSession(ctx appengine.Context, session *Session, acct *Account, user *User) {
	key := session.Key
	sessions[key] = session
	sessionToAccount[session] = acct
	sessionToUser[session] = user
	i := &memcache.Item{
		Key:    "session-" + session.Key,
		Object: session,
	}
	err := memcache.Gob.Set(ctx, i)
	if err != nil {
		ctx.Errorf(err.Error())
	}
}

func sendSession(req *http.Request, rw http.ResponseWriter, session *Session) {
	sessionHeader := Headers["session"]
	sessionKey := session.Key

	var domain string
	if reqUrl, err := url.Parse(req.Header.Get("Origin")); err != nil {
		domain = reqUrl.Host
		// If domain includes port, slice it off
		if strings.Contains(domain, ":") {
			domainParts := strings.Split(domain, ":")
			domain = domainParts[0]
		}
	}
	cookie := &http.Cookie{
		Name:   sessionHeader,
		Value:  sessionKey,
		Domain: domain,
		Path:   "/",
	}

	rw.Header().Set(sessionHeader, sessionKey)
	rw.Header().Add("Access-Control-Expose-Headers", sessionHeader)

	http.SetCookie(rw, cookie)
}

func SendSession(req *http.Request, rw http.ResponseWriter, session *Session) {
	sendSession(req, rw, session)
}

func createSession(ctx appengine.Context, acct *Account, user *User) (*Session, error) {
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
	if user != nil {
		session.User = user.GetKey(ctx)
	}
	storeSession(ctx, session, acct, user)
	storeAuthenticatedRequest(ctx, acct, session, user)
	return session, nil
}

func CreateSession(ctx appengine.Context, acct *Account, user *User) (*Session, error) {
	return createSession(ctx, acct, user)
}

func storeAuthenticatedRequest(ctx appengine.Context, acct *Account, session *Session, user *User) {
	reqId := appengine.RequestID(ctx)
	authenticatedAccounts[reqId] = acct
	authenticatedSessions[reqId] = session
	authenticatedUsers[reqId] = user
}

// ClearAuthenticatedRequest removes a request from the internal authentication mappings to both account and session
// called automatically after a request has been processed by AuthenticatedHandler and AuthenticatedFunc
func ClearAuthenticatedRequest(req *http.Request) {
	ctx := appengine.NewContext(req)
	reqId := appengine.RequestID(ctx)
	delete(authenticatedAccounts, reqId)
	delete(authenticatedSessions, reqId)
	delete(authenticatedUsers, reqId)
}

// Clears the session, optionally specified by a key, otherwise pulled from the current request
// Returns a bool for whether or not that session existed
func ClearSession(req *http.Request, sessionKey string) bool {
	ctx := appengine.NewContext(req)
	if sessionKey == "" {
		sessionKey = sessionKeyFromRequest(req)
		if sessionKey == "" {
			return false
		}
	}
	memcache.Delete(ctx, "session-"+sessionKey)
	if session, ok := sessions[sessionKey]; ok {
		delete(sessions, sessionKey)

		if _, ok = sessionToAccount[session]; ok {
			delete(sessionToAccount, session)
		}

		return true
	}
	return false
}

func getAccountFromSession(ctx appengine.Context, session *Session) (acct *Account, err error) {
	if acct, ok := sessionToAccount[session]; ok {
		return acct, nil
	}
	acctKey := session.Account
	acct = &Account{}
	if aeutils.UseNDS {
		err = nds.Get(ctx, acctKey, acct)
	} else {
		err = datastore.Get(ctx, acctKey, acct)
	}
	if err != nil {
		return nil, NoSuchSession
	}
	acct.Load(ctx)
	return
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

func getUserFromSession(ctx appengine.Context, session *Session) (user *User, err error) {
	if user, ok := sessionToUser[session]; ok {
		return user, nil
	}
	userKey := session.User
	user = &User{}
	if aeutils.UseNDS {
		err = nds.Get(ctx, userKey, user)
	} else {
		err = datastore.Get(ctx, userKey, user)
	}
	if err != nil {
		return nil, NoSuchSession
	}
	return
}
