// Package main is for dynamic libraries only
// Should always match pkg/authn/mobile.go
package main

import "C"

import (
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/authn/pkg/creds"
	"github.com/mousybusiness/authn/pkg/fireb"
	"github.com/mousybusiness/authn/pkg/pkce"
	"os"
)

//export AuthFirebase
// AuthFirebase will authenticate using Firebase flow and return the refresh token
func AuthFirebase(title, port, clientID, clientSecret, apiKey, redirectURL *C.char) *C.char {
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

	r := a.Auth()

	b, err := json.Marshal(r)
	if err != nil {
		return nil
	}

	p := C.CString(string(b))
	return p
}

//export ReauthFirebase
// ReauthFirebase will get a new ID token using the provided refresh token and Firebase credentials
func ReauthFirebase(title, port, clientID, clientSecret, apiKey, redirectURL, refreshToken *C.char) *C.char {
	a, err := fireb.New(fireb.Config{
		Title:        C.GoString(title),
		Port:         C.GoString(port),
		ClientID:     C.GoString(clientID),
		ClientSecret: C.GoString(clientSecret),
		APIKey:       C.GoString(apiKey),
		RedirectURL:  C.GoString(redirectURL),
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using Firebase, couldn't create Firebase provider, err: %v\n", err)
		return nil
	}

	r, err := a.Refresh(creds.RefreshToken(C.GoString(refreshToken)))
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

//export AuthPKCE
// AuthPKCE will authenticate using PKCE flow and return the refresh token
func AuthPKCE(title, port, clientID, issuer, authURL, tokenURL, redirectURL *C.char) *C.char {
	a, err := pkce.New(pkce.Config{
		Title:       C.GoString(title),
		Port:        C.GoString(port),
		ClientID:    C.GoString(clientID),
		Issuer:      C.GoString(issuer),
		AuthURL:     C.GoString(authURL),
		TokenURL:    C.GoString(tokenURL),
		RedirectURL: C.GoString(redirectURL),
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using PKCE, couldn't create PKCE provider, err: %v\n", err)
		return nil
	}

	r := a.Auth()

	b, err := json.Marshal(r)
	if err != nil {
		return nil
	}

	return C.CString(string(b))
}

//export ReauthPKCE
// ReauthPKCE will get a new ID token using the provided refresh token and PKCE credentials
func ReauthPKCE(title, port, clientID, issuer, authURL, tokenURL, redirectURL, refreshToken *C.char) *C.char {
	a, err := pkce.New(pkce.Config{
		Title:       C.GoString(title),
		Port:        C.GoString(port),
		ClientID:    C.GoString(clientID),
		Issuer:      C.GoString(issuer),
		AuthURL:     C.GoString(authURL),
		TokenURL:    C.GoString(tokenURL),
		RedirectURL: C.GoString(redirectURL),
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using PKCE, couldn't create PKCE provider, err: %v\n", err)
		return nil
	}

	r, err := a.Refresh(creds.RefreshToken(C.GoString(refreshToken)))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using PKCE, couldn't refresh token, err: %v\n", err)
		return nil
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil
	}

	return C.CString(string(b))
}

func main() {}
