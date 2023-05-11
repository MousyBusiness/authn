// Package main is for dynamic libraries only
// Should always match pkg/authn/mobile.go
package main

import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/authn/pkg/creds"
	"github.com/mousybusiness/authn/pkg/fireb"
	"os"
)

var ctx context.Context
var cancel context.CancelFunc

//export AuthFirebase
// AuthFirebase will authenticate using Firebase flow and return the refresh token
func AuthFirebase(title, port, clientID, clientSecret, apiKey, redirectURL *C.char) *C.char {
	if cancel != nil {
		cancel()
	}
	ctx, cancel = context.WithCancel(context.Background()) // Create a global context to use so we can cancel

	a, err := fireb.New(fireb.Config{
		Title:        C.GoString(title),
		Port:         C.GoString(port),
		ClientID:     C.GoString(clientID),
		ClientSecret: C.GoString(clientSecret),
		APIKey:       C.GoString(apiKey),
		RedirectURL:  C.GoString(redirectURL),
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using Firebase: %v\n", err)
		return nil
	}

	r := a.Auth(ctx)
	if r == nil {
		return nil
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil
	}

	return C.CString(string(b))
}

//export ReauthFirebase
// ReauthFirebase will get a new ID token using the provided refresh token and Firebase credentials
func ReauthFirebase(apiKey, refreshToken *C.char) *C.char {
	if cancel != nil {
		cancel()
	}
	ctx, cancel = context.WithCancel(context.Background()) // Create a global context to use so we can cancel

	a, err := fireb.New(fireb.Config{
		APIKey: C.GoString(apiKey),
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using Firebase, couldn't create Firebase provider, err: %v\n", err)
		return nil
	}

	r, err := a.Refresh(ctx, creds.RefreshToken(C.GoString(refreshToken)))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using Firebase, couldn't refresh token, err: %v\n", err)
		return nil
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil
	}

	return C.CString(string(b))
}

//export Abort
// Abort will cancel any existing requests if possible
func Abort() {
	if cancel != nil {
		cancel()
	}
}

////export AuthPKCE
//// AuthPKCE will authenticate using PKCE 
//	return C.CString(string(b))
//}

func main() {}
