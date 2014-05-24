package aeutils

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"appengine"
	"appengine/datastore"
)

// type ApiResponse is a generic API response struct
type ApiResponse struct {
	Code    int                    `json:"code"`
	Message string                 `json:"message"`
	Result  interface{}            `json:"result"`
	Data    map[string]interface{} `json:"data"` // Generic extra data to be sent along in response
}

func GenerateUniqueSlug(ctx appengine.Context, kind string, s string) (slug string) {
	slug = GenerateSlug(s)
	others, err := datastore.NewQuery(kind).
		Filter("Slug = ", slug).
		Count(ctx)
	if err != nil {
		ctx.Errorf("[utils/GenerateUniqueSlug] %v", err.Error())
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
			ctx.Errorf("[utils/GenerateUniqueSlug] %v", err.Error())
			return ""
		}
		counter = counter + 1
	}
	return slug
}

func GenerateSlug(s string) (slug string) {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ' ', r == '-':
			return '-'
		case r == '_', unicode.IsLetter(r), unicode.IsDigit(r):
			return r
		default:
			return -1
		}
		return -1
	}, strings.ToLower(strings.TrimSpace(s)))
}

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
	//Store in memcache
	key, err = datastore.Put(ctx, key, obj)
	if err != nil {
		ctx.Errorf("[utils/Save]: %v", err.Error())
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

// func ExistsInDatastore takes an appengine Context and an interface checks if that interface already exists in datastore
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

// Takes a reflect kind and returns a valid string value matching that kind
// Strips off any package namespacing, so 'accounts.Account' becomes just 'Account'
func getDatastoreKind(kind reflect.Type) (dsKind string) {
	dsKind = kind.String()
	if li := strings.LastIndex(dsKind, "."); li >= 0 {
		//Format kind to be in a standard format used for datastore
		dsKind = dsKind[li+1:]
	}
	return
}
