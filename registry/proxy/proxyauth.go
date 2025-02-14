package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
)

const challengeHeader = "Docker-Distribution-Api-Version"

// authChallenger encapsulates a request to the upstream to establish credential challenges
type authChallenger interface {
	tryEstablishChallenges(context.Context) error
	challengeManager() challenge.Manager
	credentialStore() auth.CredentialStore
}

type remoteAuthChallenger struct {
	remoteURL  url.URL
	httpClient *http.Client
	sync.Mutex
	cm challenge.Manager
	cs auth.CredentialStore
}

func (r *remoteAuthChallenger) credentialStore() auth.CredentialStore {
	return r.cs
}

func (r *remoteAuthChallenger) challengeManager() challenge.Manager {
	return r.cm
}

// tryEstablishChallenges will attempt to get a challenge type for the upstream if none currently exist
func (r *remoteAuthChallenger) tryEstablishChallenges(ctx context.Context) error {
	r.Lock()
	defer r.Unlock()

	remoteURL := r.remoteURL
	remoteURL.Path = "/v2/"
	challenges, err := r.cm.GetChallenges(remoteURL)
	if err != nil {
		return err
	}

	if len(challenges) > 0 {
		return nil
	}

	// establish challenge type with upstream
	if err := ping(r.cm, remoteURL.String(), challengeHeader, r.httpClient); err != nil {
		return err
	}

	dcontext.GetLogger(ctx).Infof("Challenge established with upstream (URL: %s, cm: %+v)\n", remoteURL.String(), r.cm)
	return nil
}

type userpass struct {
	username string
	password string
}

type tokenCredentials struct {
	creds map[string]userpass
}

func (c tokenCredentials) Basic(u *url.URL) (string, string) {
	up := c.creds[u.String()]

	return up.username, up.password
}

func (c tokenCredentials) RefreshToken(u *url.URL, service string) string {
	return ""
}

func (c tokenCredentials) SetRefreshToken(u *url.URL, service, token string) {
}

type basicCredentials struct {
	creds     userpass
	urlPrefix string
}

func (c basicCredentials) Basic(u *url.URL) (string, string) {
	if strings.HasPrefix(u.String(), c.urlPrefix) {
		return c.creds.username, c.creds.password
	}

	return "", ""
}

func (c basicCredentials) RefreshToken(u *url.URL, service string) string {
	return ""
}

func (c basicCredentials) SetRefreshToken(u *url.URL, service, token string) {
}

// configureTokenAuth stores credentials for challenge responses
func configureTokenAuth(username, password, remoteURL string, httpClient *http.Client) (auth.CredentialStore, error) {
	creds := map[string]userpass{}

	authURLs, err := getTokenAuthURLs(remoteURL, httpClient)
	if err != nil {
		return nil, err
	}

	if len(authURLs) > 0 {
		for _, url := range authURLs {
			dcontext.GetLogger(context.Background()).Infof("Discovered token authentication URL: %s", url)
			creds[url] = userpass{
				username: username,
				password: password,
			}
		}

		return tokenCredentials{creds: creds}, nil
	}

	dcontext.GetLogger(context.Background()).Infof("Will use Basic authentication for URL prefix: %s", remoteURL)
	credentials := basicCredentials{
		creds: userpass{
			username: username,
			password: password,
		},
		urlPrefix: remoteURL,
	}

	return credentials, nil
}

func getTokenAuthURLs(remoteURL string, httpClient *http.Client) ([]string, error) {
	authURLs := []string{}

	resp, err := httpClient.Get(remoteURL + "/v2/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	for _, c := range challenge.ResponseChallenges(resp) {
		if strings.EqualFold(c.Scheme, "bearer") {
			authURLs = append(authURLs, c.Parameters["realm"])
		}
	}

	return authURLs, nil
}

func ping(manager challenge.Manager, endpoint, versionHeader string, httpClient *http.Client) error {
	resp, err := httpClient.Get(endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return manager.AddResponse(resp)
}
