// Package authn is for go-mobile only
// Should always match cmd/lib/main.go
package authn

import "C"
import (
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/authn/pkg/creds"
	"github.com/mousybusiness/authn/pkg/fireb"
	"os"
)

// AuthFirebase will authenticate using Firebase flow and return the refresh token
func AuthFirebase(title, port, clientID, clientSecret, apiKey, redirectURL string) string {
	a, err := fireb.New(fireb.Config{
		Title:        title,
		Port:         port,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		APIKey:       apiKey,
		RedirectURL:  redirectURL,
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using Firebase: %v\n", err)
		return ""
	}

	r := a.Auth()
	return string(r.RefreshToken)
}

// ReauthFirebase will get a new ID token using the provided refresh token and Firebase credentials
func ReauthFirebase(apiKey, refreshToken string) string {
	a, err := fireb.New(fireb.Config{
		APIKey: apiKey,
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using Firebase, couldn't create Firebase provider, err: %v\n", err)
		return ""
	}

	r, err := a.Refresh(creds.RefreshToken(refreshToken))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using Firebase, couldn't refresh token, err: %v\n", err)
		return ""
	}

	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}

	return string(b)
}

//
//// AuthPKCE will authenticate using PKCE flow and return the refresh token
//func AuthPKCE(title, port, clientID, issuer, authURL, tokenURL, redirectURL string) string {
//	a, err := pkce.New(pkce.Config{
//		Title:       title,
//		Port:        port,
//		ClientID:    clientID,
//		Issuer:      issuer,
//		AuthURL:     authURL,
//		TokenURL:    tokenURL,
//		RedirectURL: redirectURL,
//	})
//
//	if err != nil {
//		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using PKCE, couldn't create PKCE provider, err: %v\n", err)
//		return ""
//	}
//
//	r := a.Auth()
//
//	b, err := json.Marshal(r)
//	if err != nil {
//		return ""
//	}
//
//	return string(b)
//}
//
//// ReauthPKCE will get a new ID token using the provided refresh token and PKCE credentials
//func ReauthPKCE(title, port, clientID, issuer, authURL, tokenURL, redirectURL, refreshToken string) string {
//	a, err := pkce.New(pkce.Config{
//		Title:       title,
//		Port:        port,
//		ClientID:    clientID,
//		Issuer:      issuer,
//		AuthURL:     authURL,
//		TokenURL:    tokenURL,
//		RedirectURL: redirectURL,
//	})
//
//	if err != nil {
//		_, _ = fmt.Fprintf(os.Stderr, "Failed to authenticate using PKCE, couldn't create PKCE provider, err: %v\n", err)
//		return ""
//	}
//
//	r, err := a.Refresh(creds.RefreshToken(refreshToken))
//	if err != nil {
//		_, _ = fmt.Fprintf(os.Stderr, "Failed to reauthenticate using PKCE, couldn't refresh token, err: %v\n", err)
//		return ""
//	}
//
//	b, err := json.Marshal(r)
//	if err != nil {
//		return ""
//	}
//
//	return string(b)
//}
