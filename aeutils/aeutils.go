// Package aeutils provides some useful utilities for working with
// structs and other objects within the Google App Engine architecture.
package aeutils

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/mrvdot/golang-utils"

	"appengine"
	"appengine/datastore"
)

// GenerateUniqueSlug generates a slug that's unique within the datastore for this type
// Uses utils.GenerateSlug for initial slug, and appends "-N" where N is an auto-incrementing number
// Until it finds a slug that doesn't already exist for this kind
func GenerateUniqueSlug(ctx appengine.Context, kind string, s string) (slug string) {
	slug = utils.GenerateSlug(s)
	others, err := datastore.NewQuery(kind).
		Filter("Slug = ", slug).
		Count(ctx)
	if err != nil {
		ctx.Errorf("[aeutils/GenerateUniqueSlug] %v", err.Error())
		return ""
	}
	if others == 0 {
		return slug
	}
	counter := 2
	baseSlug := slug
	for others > 0 {
		slug = fmt.Sprintf("%v-%d", baseSlug, counter)
		others, err = datastore.NewQuery(kind).
			Filter("Slug = ", slug).
			Count(ctx)
		if err != nil {
			ctx.Errorf("[aeutils/GenerateUniqueSlug] %v", err.Error())
			return ""
		}
		counter = counter + 1
	}
	return slug
}

// Save takes an appengine.Context and an struct (or pointer to struct) to save in the datastore
// Uses reflection to validate obj is able to be saved. Additionally checks for:
// - Method 'BeforeSave' that receives appengine.Context as it's first parameter
//   This can be used for any on save actions that need to be performed (generate a slug, store LastUpdated, or create Key field (see below))
// - Field 'Key' of kind *datastore.Key. If exists and has a valid key, uses that for storing in datastore
// 	 ** Important. Due to datastore limitations, this field must not actually be stored in the datastore (ie, needs struct tag `datastore:"-")
// - Field 'ID' of kind int64 to be used as the numeric ID for a datastore key
//	 If key was not retrieved from Key field, ID field is used to create a new key based on that ID
//	 If struct has ID field but no value for it, Save allocates an ID from the datastore and sets it in that field before saving
// - Method 'AfterSave' that receives appengine.Context and *datastore.Key as it's parameters
//   Useful for any post save processing that you might want to do
// Finally, ID and Key fields (if they exist) are set with any generated values from Saving obj
func Save(ctx appengine.Context, obj interface{}) (key *datastore.Key, err error) {
	kind, val := reflect.TypeOf(obj), reflect.ValueOf(obj)
	str := val
	if val.Kind().String() == "ptr" {
		kind, str = kind.Elem(), val.Elem()
	}
	if str.Kind().String() != "struct" {
		return nil, errors.New("Must pass a valid object to struct")
	}
	dsKind := getDatastoreKind(kind)
	if bsMethod := val.MethodByName("BeforeSave"); bsMethod.IsValid() {
		bsMethod.Call([]reflect.Value{reflect.ValueOf(ctx)})
	}
	//check for key field first
	keyField := str.FieldByName("Key")
	if keyField.IsValid() {
		keyInterface := keyField.Interface()
		key, _ = keyInterface.(*datastore.Key)
	}
	idField := str.FieldByName("ID")
	if key == nil {
		if idField.IsValid() && idField.Int() != 0 {
			key = datastore.NewKey(ctx, dsKind, "", idField.Int(), nil)
		} else {
			newId, _, err := datastore.AllocateIDs(ctx, dsKind, nil, 1)
			if err == nil {
				if idField.IsValid() {
					idField.SetInt(newId)
				}
				key = datastore.NewKey(ctx, dsKind, "", newId, nil)
			} else {
				ctx.Errorf("Failed to allocate new ID for this user: %v", err.Error())
				key = datastore.NewIncompleteKey(ctx, dsKind, nil)
			}
		}
	}
	key, err = datastore.Put(ctx, key, obj)
	if err != nil {
		ctx.Errorf("[aeutils/Save]: %v", err.Error())
	} else {
		if keyField.IsValid() {
			keyField.Set(reflect.ValueOf(key))
		}
		if idField.IsValid() {
			idField.SetInt(key.IntID())
		}
		if asMethod := val.MethodByName("AfterSave"); asMethod.IsValid() {
			asMethod.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(key)})
		}
	}
	return
}

// ExistsInDatastore takes an appengine Context and an interface checks if that interface already exists in datastore
// Will call any 'BeforeSave' method as appropriate, in case that method sets up a 'Key' field, otherwise checks for an ID field
// and assumes that's the datastore IntID
func ExistsInDatastore(ctx appengine.Context, obj interface{}) bool {
	kind, val := reflect.TypeOf(obj), reflect.ValueOf(obj)
	str := val
	if val.Kind().String() == "ptr" {
		kind, str = kind.Elem(), val.Elem()
	}
	if str.Kind().String() != "struct" {
		return false
	}
	dsKind := getDatastoreKind(kind)
	if bsMethod := val.MethodByName("BeforeSave"); bsMethod.IsValid() {
		bsMethod.Call([]reflect.Value{reflect.ValueOf(ctx)})
	}
	var key *datastore.Key
	//check for key field first
	keyField := str.FieldByName("Key")
	if keyField.IsValid() {
		keyInterface := keyField.Interface()
		key, _ = keyInterface.(*datastore.Key)
	}
	idField := str.FieldByName("ID")
	if key == nil {
		if idField.IsValid() && idField.Int() != 0 {
			key = datastore.NewKey(ctx, dsKind, "", idField.Int(), nil)
		}
	}
	if key == nil {
		return false
	}
	err := datastore.Get(ctx, key, obj)
	if err != nil {
		return false
	}
	return true
}

// getDatastoreKind takes a reflect kind and returns a valid string value matching that kind
// Strips off any package namespacing, so 'accounts.Account' becomes just 'Account'
func getDatastoreKind(kind reflect.Type) (dsKind string) {
	dsKind = kind.String()
	if li := strings.LastIndex(dsKind, "."); li >= 0 {
		//Format kind to be in a standard format used for datastore
		dsKind = dsKind[li+1:]
	}
	return
}
