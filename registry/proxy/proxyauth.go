package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
)

const challengeHeader = "Docker-Distribution-Api-Version"

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
			context.GetLogger(context.Background()).Infof("Discovered token authentication URL: %s", url)
			creds[url] = userpass{
				username: username,
				password: password,
			}
		}

		return tokenCredentials{creds: creds}, nil
	}

	context.GetLogger(context.Background()).Infof("Will use Basic authentication for URL prefix: %s", remoteURL)
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
