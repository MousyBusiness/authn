// Package main is for dynamic libraries only
// Should always match pkg/authn/mobile.go
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/authn/pkg/creds"
	"github.com/mousybusiness/authn/pkg/fireb"
	"os"
	"unsafe"
)

var allocated = make(map[string]*C.char)

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
	hash := fmt.Sprintf("%x", md5.Sum(b))

	if _, ok := allocated[hash]; ok {
		_, _ = fmt.Fprintf(os.Stderr, "Hash already exist!: %v\n", hash)
		Free(p)
	}

	allocated[hash] = p

	return p
}

//export ReauthFirebase
// ReauthFirebase will get a new ID token using the provided refresh token and Firebase credentials
func ReauthFirebase(apiKey, refreshToken *C.char) *C.char {
	a, err := fireb.New(fireb.Config{
		APIKey: C.GoString(apiKey),
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

	p := C.CString(string(b))
	hash := fmt.Sprintf("%x", md5.Sum(b))

	if _, ok := allocated[hash]; ok {
		_, _ = fmt.Fprintf(os.Stderr, "Hash already exist!: %v\n", hash)
		Free(p)
	}

	allocated[hash] = p

	return p
}

//export Free
// Free will release memory allocated for token json
func Free(json *C.char) bool {
	if json == nil {
		_, _ = fmt.Fprintf(os.Stderr, "JSON string is nil!\n")
		return false
	}

	s := C.GoString(json)
	if len(s) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "JSON string is empty!\n")
		return false
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(s)))
	if p, ok := allocated[hash]; ok {
		_, _ = fmt.Fprintf(os.Stdout, "Freeing %v\n", hash)
		C.free(unsafe.Pointer(p))
		_, _ = fmt.Fprintf(os.Stdout, "Free %v\n", hash)
		delete(allocated, hash)
		return true
	}

	return false
}

////export AuthPKCE
//// AuthPKCE will authenticate using PKCE flow and return the refresh token
//func AuthPKCE(title, port, clientID, issuer, authURL, tokenURL, redirectURL *C.char) *C.char {
//	a, err := pkce.New(pkce.Config{
//		Title:       C.GoString(title),
//		Port:        C.GoString(port),
//		ClientID:    C.GoString(clientID),
//		Issuer:      C.GoString(issuer),
//		AuthURL:     C.GoString(authURL),
//		TokenURL:    C.GoString(tokenURL),
//		RedirectURL: C.GoString(redirectURL),
//	})
//
//	if err != nil {
//		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using PKCE, couldn't create PKCE provider, err: %v\n", err)
//		return nil
//	}
//
//	r := a.Auth()
//
//	b, err := json.Marshal(r)
//	if err != nil {
//		return nil
//	}
//
//	return C.CString(string(b))
//}
//
////export ReauthPKCE
//// ReauthPKCE will get a new ID token using the provided refresh token and PKCE credentials
//func ReauthPKCE(title, port, clientID, issuer, authURL, tokenURL, redirectURL, refreshToken *C.char) *C.char {
//	a, err := pkce.New(pkce.Config{
//		Title:       C.GoString(title),
//		Port:        C.GoString(port),
//		ClientID:    C.GoString(clientID),
//		Issuer:      C.GoString(issuer),
//		AuthURL:     C.GoString(authURL),
//		TokenURL:    C.GoString(tokenURL),
//		RedirectURL: C.GoString(redirectURL),
//	})
//
//	if err != nil {
//		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using PKCE, couldn't create PKCE provider, err: %v\n", err)
//		return nil
//	}
//
//	r, err := a.Refresh(creds.RefreshToken(C.GoString(refreshToken)))
//	if err != nil {
//		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using PKCE, couldn't refresh token, err: %v\n", err)
//		return nil
//	}
//
//	b, err := json.Marshal(r)
//	if err != nil {
//		return nil
//	}
//
//	return C.CString(string(b))
//}

func main() {}
