package accounts

import (
	"testing"
	. "gopkg.in/check.v1"

	"github.com/mrvdot/appengine/aeutils"
	"appengine/aetest"
	"appengine/datastore"
)

// Setup test suite
type MySuite struct{}

var (
	_            = Suite(&MySuite{})
	elType       = "MyType"
	elIdentifier = "MyIdentifier"
	ctx          aetest.Context
	validAccount = &Account{
		Name:   "Valid Account",
		Active: true,
	}
)

// Hook up gocheck testing library to our usual testing tool
func Test(t *testing.T) {
	TestingT(t)
}

func (s *MySuite) SetUpSuite(c *C) {
	var err error
	ctx, err = aetest.NewContext(nil)
	if err != nil {
		c.Fatal("Failed to create appengine context")
	}
	// Create an initial account for testing
	key, err := aeutils.Save(ctx, validAccount)
	c.Assert(err, IsNil)
	// Do a get to make sure eventual consistency is ready for testing
	_ = datastore.Get(ctx, key, &Account{})
}

func (s *MySuite) TearDownSuite(c *C) {
	ctx.Close()
}
