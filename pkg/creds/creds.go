package creds

import (
	"time"
)

type (
	// AccessToken can provide access to resources requested via 'scopes'
	AccessToken  string

	// IDToken is a signed JWT which contains verified information
	// about the authenticated user. Custom claims can be added
	// to the IDToken via your user management technology.
	IDToken      string

	// RefreshToken is used to refresh user credentials
	// without requiring user input. Keep this secure.
	RefreshToken string

	// Credentials is a container for the returned authentication data.
	Credentials  struct {
		UID string
		AccessToken
		IDToken
		RefreshToken
		Expiry time.Time
	}
)
