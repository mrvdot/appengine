package accounts

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/mrvdot/appengine-utils"

	"appengine"
	"appengine/datastore"
)

var (
	authenticatedAccounts = map[string]*Account{}
	authenticatedSessions = map[string]*Session{}
	sessionToAccount      = map[*Session]*Account{}
	sessions              = map[string]*Session{}
	Unauthenticated       = errors.New("No account has been authenticated for this request")
	NoSuchSession         = errors.New("No account matches that session")
	NoSuchAccount         = errors.New("No account matches that slug")
	InvalidApiKey         = errors.New("API Key does not match account")
	SessionExpired        = errors.New("Session has expired, please reauthenticate")
	// Strings used for checking account info in request headers
	Headers = map[string]string{
		"account": "X-account", // Account slug
		"key":     "X-key",     // Account key
		"session": "X-session", // Session key
	}
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

// func BeforeSave is called as part of utils.Save prior to storing in the datastore
// serves to set a default account name and slug, as well as ApiKey and Created timestamp
func (acct *Account) BeforeSave(ctx appengine.Context) {
	if acct.Name == "" {
		acct.Name = fmt.Sprintf("Account-%v", rand.Int())
	}
	if acct.Slug == "" {
		acct.Slug = utils.GenerateUniqueSlug(ctx, "Account", acct.Name)
		acct.Created = time.Now()
		h := md5.New()
		io.WriteString(h, fmt.Sprintf("%d%d%d", rand.Int(), rand.Int(), rand.Int()))
		apiKeyBytes := h.Sum(nil)
		acct.ApiKey = fmt.Sprintf("%x", apiKeyBytes)
	}
}

// func Load initializes an account with any necessary calculated values
func (acct *Account) Load(ctx appengine.Context) {
	acct.GetKey(ctx)
}

type Session struct {
	Key         string         //Session Key provided for identification
	Account     *datastore.Key //Key to actual account
	Initialized time.Time      //Time session was first created
	LastUsed    time.Time      //Last time session was used
	TTL         time.Duration  //How long should this session be valid after LastUsed
}
