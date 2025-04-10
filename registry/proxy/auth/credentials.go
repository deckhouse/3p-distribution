package auth

import (
	"context"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"net/url"
	"strings"
	"sync"
)

// Credentials stores the username and password for authentication.
type Credentials struct {
	username string
	password string
}

// GetCredentials returns the stored username and password.
func (c Credentials) GetCredentials() (string, string) {
	return c.username, c.password
}

// BasicAuthCredentials manages authentication using basic credentials (username and password).
type BasicAuthCredentials struct {
	authURL string
	creds   Credentials
	mutex   sync.Mutex
}

// NewBasicAuthCredentials creates a new instance of BasicAuthCredentials with the provided username, password, and authentication URL.
func NewBasicAuthCredentials(username, password, authURL string) *BasicAuthCredentials {
	return &BasicAuthCredentials{
		authURL: authURL,
		creds:   Credentials{username: username, password: password},
	}
}

// Basic returns the basic authentication credentials if the provided URL matches the stored auth URL.
func (c *BasicAuthCredentials) Basic(authURL *url.URL) (string, string) {
	if authURL == nil {
		return "", ""
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if strings.HasPrefix(authURL.String(), c.authURL) {
		return c.creds.GetCredentials()
	}
	return "", ""
}

// RefreshToken is a placeholder method for refreshing the authentication token.
func (c *BasicAuthCredentials) RefreshToken(u *url.URL, service string) string {
	return ""
}

// SetRefreshToken is a placeholder method for setting the refresh token.
func (c *BasicAuthCredentials) SetRefreshToken(u *url.URL, service, token string) {}

// UpdateCredentials updates the authentication challenges for the given URL (currently no-op for basic auth).
func (c *BasicAuthCredentials) UpdateCredentials(ctx context.Context, authURL string, challenges []challenge.Challenge) {
}

// TokenAuthCredentials stores credentials for different authentication realms (using token-based authentication).
type TokenAuthCredentials struct {
	authURL  string
	creds    Credentials
	realmSet map[string]struct{}
	mutex    sync.Mutex
}

// NewTokenAuthCredentials creates a new instance of TokenAuthCredentials with the provided username, password, and authentication URL.
func NewTokenAuthCredentials(username, password, authURL string) *TokenAuthCredentials {
	return &TokenAuthCredentials{
		authURL:  authURL,
		creds:    Credentials{username: username, password: password},
		realmSet: make(map[string]struct{}),
	}
}

// Basic returns the credentials for a given realm URL if available.
func (c *TokenAuthCredentials) Basic(realmURL *url.URL) (string, string) {
	if realmURL == nil {
		return "", ""
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.realmSet[realmURL.String()]; exists {
		return c.creds.GetCredentials()
	}
	return "", ""
}

// RefreshToken is a placeholder method for refreshing the authentication token.
func (c *TokenAuthCredentials) RefreshToken(u *url.URL, service string) string {
	return ""
}

// SetRefreshToken is a placeholder method for setting the refresh token.
func (c *TokenAuthCredentials) SetRefreshToken(u *url.URL, service, token string) {}

// UpdateCredentials updates stored credentials for a given set of realm URLs.
// It replaces the existing set of realm URLs with the new one.
func (c *TokenAuthCredentials) UpdateCredentials(ctx context.Context, authURL string, challenges []challenge.Challenge) {
	if !strings.HasPrefix(authURL, c.authURL) {
		return
	}

	newRealmSet := make(map[string]struct{}, len(challenges))

	// Collect all the realm URLs from the challenges in a single pass
	for _, ch := range challenges {
		if strings.EqualFold(ch.Scheme, "bearer") {
			if realm, exists := ch.Parameters["realm"]; exists {
				newRealmSet[realm] = struct{}{}
			}
		}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.realmSet = newRealmSet
}
