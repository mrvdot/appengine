package accounts

import (
	"fmt"
	. "gopkg.in/check.v1"
)

func (s *MySuite) TestGetAccountFromSlug(c *C) {
	// First test valid account
	acct, err := getAccountFromSlug(ctx, validAccount.Slug, validAccount.ApiKey)
	c.Assert(err, IsNil)
	// Test on slug since deep equals fails with different key pointers, etc
	c.Assert(acct.Slug, Equals, validAccount.Slug)

	// Now test valid account but wrong key
	unauthAcct, err := getAccountFromSlug(ctx, validAccount.Slug, fmt.Sprintf("%v-other", validAccount.ApiKey))
	c.Assert(unauthAcct, IsNil)
	c.Assert(err, Equals, InvalidApiKey)

	// Now test nonexistent account
	wrongAcct, err := getAccountFromSlug(ctx, fmt.Sprintf("%v-other", validAccount.Slug), "12345")
	c.Assert(wrongAcct, IsNil)
	c.Assert(err, Equals, NoSuchAccount)
}

// This test authenticates an account, validates that a session was created,
// and then that we can retreive the original account via that session
func (s *MySuite) TestAuthentication(c *C) {
	session, err := authenticateAccount(ctx, validAccount.Slug, validAccount.ApiKey)
	c.Assert(err, IsNil)
	sessionKey := session.Key
	acct, session2, err := authenticateSession(ctx, sessionKey)
	c.Assert(err, IsNil)
	c.Assert(session, DeepEquals, session2)
	c.Assert(acct.Slug, Equals, validAccount.Slug)
}
