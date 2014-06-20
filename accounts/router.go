package accounts

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/mrvdot/appengine/aeutils"
	"github.com/mrvdot/golang-utils"

	"appengine"
)

var (
	// Router instance for accounts, made public to allow for adding additional routes
	Router        *mux.Router
	SubrouterPath = "accounts"
)

// func InitRouter attaches two routes "new" and "authenticate" to a subpath
// to the http handler
// If an empty string is passed for the subpath, the default SubrouterPath is used
func InitRouter(subpath string) {
	if subpath == "" {
		subpath = SubrouterPath
	} else {
		SubrouterPath = subpath
	}
	Router = mux.NewRouter()
	ar := Router.PathPrefix(fmt.Sprintf("/%v", SubrouterPath)).Subrouter()
	ar.HandleFunc("/new", newAccount).
		Methods("POST").
		Name("CreateAccount")
	ar.HandleFunc("/authenticate", authenticate).
		Methods("POST").
		Name("Authenticate")
	http.Handle(fmt.Sprintf("/%v/", SubrouterPath), utils.CorsHandler(Router))
}

// func newAccount creates a new request based on the "account" parameter passed in
func newAccount(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	out := json.NewEncoder(rw)
	response := &utils.ApiResponse{}
	acct := &Account{}
	name := req.FormValue("account")
	if name != "" {
		acct = &Account{
			Name:   name,
			Active: true,
		}
	} else {
		dec := json.NewDecoder(req.Body)
		defer req.Body.Close()
		err := dec.Decode(acct)
		if err != nil {
			if err == io.EOF {
				response.Code = http.StatusBadRequest
				response.Message = "Account name must be provided"
			} else {
				response.Code = http.StatusInternalServerError
				response.Message = err.Error()
			}
			out.Encode(response)
			return
		}
	}
	_, err := aeutils.Save(ctx, acct)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.Message = "Error saving new account: " + err.Error()
		out.Encode(response)
		return
	}
	response.Code = 200
	response.Result = acct
	out.Encode(response)
}

//func authenticate takes a request and authenticates it
func authenticate(rw http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	out := json.NewEncoder(rw)
	data := &utils.ApiResponse{}
	_, err := AuthenticateRequest(req)
	session, err := GetSession(ctx)
	if err != nil {
		ctx.Errorf(err.Error())
		data.Code = 403
		data.Message = err.Error()
	} else {
		data.Code = 200
		data.Data = map[string]interface{}{
			"session": session.Key,
		}
	}
	out.Encode(data)
}
