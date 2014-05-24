package aeutils

import (
	"testing"
	. "launchpad.net/gocheck"
	"appengine"
	"appengine/aetest"
	"appengine/datastore"
)

type MySuite struct{}
type DummyObject struct {
	Key              *datastore.Key
	ID               int64
	Slug             string
	BeforeSaveCalled bool
	AfterSaveCalled  bool
}

func (d *DummyObject) BeforeSave(ctx appengine.Context) {
	d.BeforeSaveCalled = true
}

func (d *DummyObject) AfterSave(ctx appengine.Context, key *datastore.Key) {
	d.AfterSaveCalled = true
}

var (
	_   = Suite(&MySuite{})
	ctx aetest.Context
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
}

func (s *MySuite) TearDownSuite(c *C) {
	ctx.Close()
}

func (s *MySuite) TestGenerateSlug(c *C) {
	testString := "My awesome string"
	want := "my-awesome-string"
	slug := GenerateSlug(testString)
	c.Assert(slug, Equals, want)
}

func (s *MySuite) TestGenerateUniqueSlug(c *C) {
	testString := "My awesome string"
	want1 := "my-awesome-string"
	want2 := "my-awesome-string-2"
	slug1 := GenerateUniqueSlug(ctx, "DummyObject", testString)
	c.Assert(slug1, Equals, want1)
	dummyObj := &DummyObject{
		Slug: slug1,
	}
	key, err := datastore.Put(ctx, datastore.NewIncompleteKey(ctx, "DummyObject", nil), dummyObj)
	if err != nil {
		c.Errorf("Failed to store dummyObj: %v", err.Error())
	}
	// Have to retrieve from datastore again, otherwise 'eventual consistency' makes this test not work
	dummyObj2 := &DummyObject{}
	datastore.Get(ctx, key, dummyObj2)
	slug2 := GenerateUniqueSlug(ctx, "DummyObject", testString)
	c.Assert(slug2, Equals, want2)
}

func (s *MySuite) TestSave(c *C) {
	dummy := &DummyObject{
		Slug: "my-awesome-string",
	}

	key, err := Save(ctx, dummy)
	if err != nil {
		c.Errorf("Failed to save dummy object: %v", err.Error())
		return
	}

	// Confirm key was properly set
	c.Assert(dummy.Key, Equals, key)

	// Confirm ID was set
	c.Assert(dummy.ID, Equals, key.IntID())

	// Confirm methods were called
	c.Assert(dummy.BeforeSaveCalled, Equals, true)
	c.Assert(dummy.AfterSaveCalled, Equals, true)

	// Finally, confirm this object actually exists in datastore
	dummy2 := &DummyObject{}
	err = datastore.Get(ctx, key, dummy2)
	c.Assert(err, IsNil)
	c.Assert(dummy2.Slug, Equals, dummy.Slug)
}

func (s *MySuite) TestExistsInDatastore(c *C) {
	dummy := &DummyObject{
		Slug: "my-existent-string",
	}

	_, err := Save(ctx, dummy)
	if err != nil {
		c.Errorf("Failed to save dummy obj: %v", err.Error())
		return
	}

	dummy2 := &DummyObject{
		Slug: "my-nonexistent-string",
	}

	dummyExists := ExistsInDatastore(ctx, dummy)
	c.Assert(dummyExists, Equals, true)

	dummy2Exists := ExistsInDatastore(ctx, dummy2)
	c.Assert(dummy2Exists, Equals, false)
}
