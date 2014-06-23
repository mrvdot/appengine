package accounts

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"time"

	"code.google.com/p/go-uuid/uuid"

	"github.com/mrvdot/appengine/aeutils"

	"appengine"
	"appengine/datastore"
)

var (
	authenticatedAccounts = map[string]*Account{}
	authenticatedSessions = map[string]*Session{}
	sessionToAccount      = map[*Session]*Account{}
	sessions              = map[string]*Session{}
	// Unauthenticated is returned when a request was not successfully authenticated
	Unauthenticated = errors.New("No account has been authenticated for this request")
	// NoSuchSession is returned when the session key passed does not correspond to an active session
	NoSuchSession = errors.New("No account matches that session")
	// NoSuchAccount is returned when no account can be found matching the specified slug
	NoSuchAccount = errors.New("No account matches that slug")
	// InvalidApiKey is returned when the specified ApiKey does not match account
	InvalidApiKey = errors.New("API Key does not match account")
	// SessionExpired is returned when the specified session has not been used within Session.TTL
	SessionExpired = errors.New("Session has expired, please reauthenticate")
	// Invalid password means the password specified for a username doesn't match what we have stored
	InvalidPassword = errors.New("That password is not valid for this user")
	// Headers is a string map to header names used for checking account info in request headers
	Headers = map[string]string{
		"account": "X-account", // Account slug
		"key":     "X-key",     // Account key
		"session": "X-session", // Session key
	}
	// SessionTTL is a time.Duration for how long a session should remain valid since LastUsed
	SessionTTL = time.Duration(3 * time.Hour)
)

//type Account holds the basic information for an attached account
type Account struct {
	Key     *datastore.Key `json:"-" datastore:"-"` //Locally cached key
	Created time.Time      `json:"created"`         //When account was first created
	Name    string         `json:"name"`            //Name of account
	Slug    string         `json:"slug"`            //Unique slug
	ApiKey  string         `json:"apikey"`          //Generated API Key for this account
	Active  bool           `json:"active"`          //True if this account is active
}

type Session struct {
	Key         string         `json:"key"`         //Session Key provided for identification
	Account     *datastore.Key `json:"-"`           //Key to actual account
	Initialized time.Time      `json:"initialized"` //Time session was first created
	LastUsed    time.Time      `json:"lastUsed"`    //Last time session was used
	TTL         time.Duration  `json:"ttl"`         //How long should this session be valid after LastUsed
}

type User struct {
	Key               *datastore.Key `json:"-" datastore:"-"`
	Created           time.Time      `json:"created"`
	LastLogin         time.Time      `json:"lastLogin"`
	Username          string         `json:"username"`
	Email             string         `json:"email"`
	Password          string         `json:"password" datastore:"-"`
	EncryptedPassword []byte         `json:"-"`
	FirstName         string         `json:"firstName"`
	LastName          string         `json:"lastName"`
	Account           *datastore.Key `json:"-"`
}

// TODO - validate uniqueness for username
func (u *User) BeforeSave(ctx appengine.Context) {
	if u.Password != "" {
		pw := u.Password
		u.Password = ""
		encrypted, err := encrypt([]byte(pw))
		if err != nil {
			ctx.Errorf("Error encoding password: %v", err.Error())
			return
		}
		u.EncryptedPassword = encrypted
	}
	if u.Username == "" {
		if u.Email != "" {
			u.Username = u.Email
		} else {
			u.Username = fmt.Sprintf("%v%v", u.FirstName, u.LastName)
		}
	}
	// If we've already registered this call within an account, go ahead and assign said account to user
	if acct, _ := GetAccount(ctx); acct != nil {
		u.Account = acct.Key
	}
}

func (u *User) validatePassword(password string) bool {
	encrypted, err := encrypt([]byte(password))
	if err != nil {
		return false
	}
	return bytes.Equal(encrypted, u.EncryptedPassword)
}

func AuthenticateUser(ctx appengine.Context, username, password string) (*User, error) {
	// We only check account if it's already set, so don't worry about an error
	acct, _ := GetAccount(ctx)
	u := &User{}
	query := datastore.NewQuery("User").
		Filter("Username =", username).
		Limit(1)

	if acct != nil {
		query.Filter("Account =", acct.Key)
	}
	iter := query.Run(ctx)

	_, err := iter.Next(u)
	if err != nil {
		return nil, err
	}
	if u.validatePassword(password) {
		return u, nil
	}
	return nil, InvalidPassword
}

// func GetKey returns the datastore key for an account
func (acct *Account) GetKey(ctx appengine.Context) (key *datastore.Key) {
	if acct.Key != nil {
		key = acct.Key
	} else {
		key = datastore.NewKey(ctx, "Account", acct.Slug, 0, nil)
		acct.Key = key
	}
	return
}

// func BeforeSave is called as part of aeutils.Save prior to storing in the datastore
// serves to set a default account name and slug, as well as ApiKey and Created timestamp
func (acct *Account) BeforeSave(ctx appengine.Context) {
	if acct.Name == "" {
		acct.Name = fmt.Sprintf("Account-%v", rand.Int())
	}
	if acct.Slug == "" {
		acct.Slug = aeutils.GenerateUniqueSlug(ctx, "Account", acct.Name)
		acct.Created = time.Now()
		h := md5.New()
		io.WriteString(h, uuid.New())
		apiKeyBytes := h.Sum(nil)
		acct.ApiKey = fmt.Sprintf("%x", apiKeyBytes)
	}
}

// func Load initializes an account with any necessary calculated values
func (acct *Account) Load(ctx appengine.Context) {
	acct.GetKey(ctx)
}
