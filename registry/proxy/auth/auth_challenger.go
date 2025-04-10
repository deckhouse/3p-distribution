package auth

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/client/auth/challenge"
)

const challengeHeader = "Docker-Distribution-Api-Version"

// AuthChallengeManager defines the interface for managing authentication challenges with an upstream server.
type AuthChallengeManager interface {
	// FetchAndUpdateChallenges retrieves authentication challenges from the upstream server and updates the credentials.
	FetchAndUpdateChallenges(ctx context.Context) error
}

// CredentialStore defines the interface for storing credentials.
type CredentialStore interface {
	// UpdateCredentials updates stored credentials for a given set of realm URLs.
	UpdateCredentials(ctx context.Context, basicURL string, challenges []challenge.Challenge)
}

// NewAuthChallengeManager creates a new instance of AuthChallengeManager with the provided parameters.
func NewAuthChallengeManager(params AuthChallengeManagerParams) AuthChallengeManager {
	return &AuthChallengeManagerImpl{
		remoteURL:        params.RemoteURL,
		httpClient:       params.HttpClient,
		credentialStores: params.CredentialStores,
		challengeManager: params.ChallengeManager,
	}
}

// AuthChallengeManagerParams holds the parameters used for creating a new AuthChallengeManager.
type AuthChallengeManagerParams struct {
	RemoteURL        url.URL
	HttpClient       *http.Client
	ChallengeManager challenge.Manager
	CredentialStores []CredentialStore
}

// AuthChallengeManagerImpl is the implementation of the AuthChallengeManager interface.
type AuthChallengeManagerImpl struct {
	remoteURL        url.URL
	httpClient       *http.Client
	challengeManager challenge.Manager
	credentialStores []CredentialStore

	// Flag to indicate if the function FetchAndUpdateChallenges is already running
	mutex      sync.Mutex
	isUpdating bool
}

// FetchAndUpdateChallenges retrieves authentication challenges from the upstream registry and updates the credentials.
func (r *AuthChallengeManagerImpl) FetchAndUpdateChallenges(ctx context.Context) error {
	// Prevent concurrent execution of the function
	r.mutex.Lock()
	if r.isUpdating {
		r.mutex.Unlock()
		return nil // If already updating, do nothing
	}
	r.isUpdating = true
	r.mutex.Unlock()

	// Defer unlocking to ensure flag is reset even if an error occurs
	defer func() {
		r.mutex.Lock()
		r.isUpdating = false
		r.mutex.Unlock()
	}()

	remoteURL := r.remoteURL
	remoteURL.Path = "/v2/"
	remoteURLStr := remoteURL.String()

	resp, err := sendPing(ctx, remoteURLStr, challengeHeader, r.httpClient)
	if err != nil {
		return err
	}

	// Update challengeManager
	if err := r.challengeManager.AddResponse(resp); err != nil {
		return err
	}
	challenges, err := r.challengeManager.GetChallenges(remoteURL)
	if err != nil {
		return err
	}

	// Update credentialStore by challenges
	var wg sync.WaitGroup
	wg.Add(len(r.credentialStores))
	for _, store := range r.credentialStores {
		go func(store CredentialStore) {
			defer wg.Done()
			store.UpdateCredentials(ctx, remoteURLStr, challenges)
		}(store)
	}
	wg.Wait()

	dcontext.GetLogger(ctx).Debugf("Challenges successfully fetched and updated for upstream `%s`: %+v", remoteURLStr, r.challengeManager)
	return nil
}

// sendPing sends a request to the registry to check if it responds to authentication challenges.
func sendPing(ctx context.Context, remoteURL, versionHeader string, httpClient *http.Client) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", remoteURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, nil
}
