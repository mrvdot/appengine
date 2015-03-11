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
	"github.com/qedus/nds"

	"appengine"
	"appengine/datastore"
)

var (
	authenticatedAccounts = map[string]*Account{}
	authenticatedSessions = map[string]*Session{}
	authenticatedUsers    = map[string]*User{}
	sessionToAccount      = map[*Session]*Account{}
	sessionToUser         = map[*Session]*User{}
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
		"account":  "X-account",  // Account slug
		"key":      "X-key",      // Account key
		"session":  "X-session",  // Session key
		"username": "X-username", // Username (for auth by user instead of account)
		"password": "X-password", // Password (for auth by user)
	}
	// SessionTTL is a time.Duration for how long a session should remain valid since LastUsed
	SessionTTL = time.Duration(3 * time.Hour)
)

//type Account holds the basic information for an attached account
type Account struct {
	Key     *datastore.Key `json:"-" datastore:"-"` //Locally cached key
	ID      string         `json:"id"`
	Created time.Time      `json:"created"` //When account was first created
	Name    string         `json:"name"`    //Name of account
	Slug    string         `json:"slug"`    //Unique slug
	ApiKey  string         `json:"apikey"`  //Generated API Key for this account // TODO - encrypt this
	Active  bool           `json:"active"`  //True if this account is active
}

type Session struct {
	Key         string         `json:"key"` //Session Key provided for identification
	Account     *datastore.Key `json:"-"`   //Key to actual account
	User        *datastore.Key `json:"-"`
	Initialized time.Time      `json:"initialized"` //Time session was first created
	LastUsed    time.Time      `json:"lastUsed"`    //Last time session was used
	TTL         time.Duration  `json:"ttl"`         //How long should this session be valid after LastUsed
}

type User struct {
	Key               *datastore.Key `json:"-" datastore:"-"`
	ID                int64          `json:"id"`
	Created           time.Time      `json:"created"`
	LastLogin         time.Time      `json:"lastLogin"`
	Username          string         `json:"username"`
	Email             string         `json:"email"`
	Password          string         `json:"password" datastore:"-"`
	EncryptedPassword []byte         `json:"-"`
	FirstName         string         `json:"firstName"`
	LastName          string         `json:"lastName"`
	AccountKey        *datastore.Key `json:"-"`
	account           *Account
}

// TODO - validate uniqueness for username
// TODO - Move to PropertyLoadSaver for encryption/decryption
// TODO - Utilize MarshalJSON to remove password
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
		u.AccountKey = acct.Key
	}
	if u.Created.IsZero() {
		u.Created = time.Now()
	}
}

func (u *User) GetKey(ctx appengine.Context) (key *datastore.Key) {
	if u.Key != nil {
		key = u.Key
	} else if u.ID == 0 {
		key = datastore.NewIncompleteKey(ctx, "User", nil)
	} else {
		key = datastore.NewKey(ctx, "User", "", u.ID, nil)
		u.Key = key
	}
	return
}

func (u *User) validatePassword(password string) bool {
	decrypted, err := decrypt(u.EncryptedPassword)
	if err != nil {
		return false
	}
	return bytes.Equal([]byte(password), decrypted)
}

func (u *User) Account(ctx appengine.Context) *Account {
	if u.AccountKey == nil {
		return nil
	}
	if u.account == nil {
		acct := &Account{}
		var err error
		if aeutils.UseNDS {
			err = nds.Get(ctx, u.AccountKey, acct)
		} else {
			err = datastore.Get(ctx, u.AccountKey, acct)
		}
		if err != nil {
			ctx.Errorf("Error retrieving account for user: %v", err.Error())
			return nil
		}
		u.account = acct
	}
	return u.account
}

// Validate a username and password, returning the appropriate user object is one is found
func AuthenticateUser(ctx appengine.Context, username, password string) (*User, error) {
	u := &User{
		Username: username,
		Password: password,
	}
	err := u.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Authenticate a user based on the current values for username and password
func (u *User) Authenticate(ctx appengine.Context) error {
	query := datastore.NewQuery("User").
		Filter("Username =", u.Username).
		Limit(1)

	// We only check account if it's already set, so don't worry about an error
	acct, _ := GetAccount(ctx)
	if acct != nil {
		query.Filter("Account =", acct.Key)
	}
	iter := query.Run(ctx)

	_, err := iter.Next(u)
	if err != nil {
		if err != datastore.Done {
			ctx.Errorf("Error loading user: %v", err.Error())
		}
		// If it's just a mismatch, keep going, likely just changed structure
		if _, ok := err.(*datastore.ErrFieldMismatch); !ok {
			return err
		}
	}

	if u.validatePassword(u.Password) {
		u.LastLogin = time.Now()
		aeutils.Save(ctx, u)
		return nil
	}
	return InvalidPassword
}

// func GetKey returns the datastore key for an account
// [TODO] - Want to migrate this to use ID's for key, not slug
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
	if acct.ID == "" {
		acct.ID = uuid.New()
	}
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
	if acct.Key == nil {
		acct.GetKey(ctx)
	}
}

// func Load initializes an account with any necessary calculated values
func (acct *Account) Load(ctx appengine.Context) {
	acct.GetKey(ctx)
}

func (acct *Account) Session(ctx appengine.Context) *Session {
	if session, err := GetSession(ctx); err == nil {
		return session
	}
	session, err := createSession(ctx, acct, nil)
	if err != nil {
		ctx.Errorf("Error creating session: %v", err.Error())
		return nil
	}
	return session
}
