package auth

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/sync/singleflight"

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

	group singleflight.Group
}

// FetchAndUpdateChallenges ensures that only one concurrent fetch/update operation is executed.
// If multiple goroutines call this method simultaneously, the underlying logic will only be
// executed once (via singleflight), and all callers will receive the same result.
//
// Each caller still respects its own context. If a specific caller's context is canceled,
// it will return early with context.Canceled, but the shared operation will continue
// unaffected for the rest of the callers.
func (r *AuthChallengeManagerImpl) FetchAndUpdateChallenges(ctx context.Context) error {
	// Use DoChan to initiate or wait for the shared operation.
	// We pass context.Background() to prevent cancellation of the shared execution
	// in case the first caller's context is canceled.
	result := r.group.DoChan("fetchAndUpdateChallengesInternal", func() (interface{}, error) {
		return nil, r.fetchAndUpdateChallengesInternal(context.Background())
	})

	select {
	case <-ctx.Done():
		// This specific caller's context was canceled before the operation completed.
		// Return the cancellation error for this call only.
		return ctx.Err()

	case res := <-result:
		// The shared operation completed. Return its result (or error) to the caller.
		return res.Err
	}
}

// fetchAndUpdateChallengesInternal performs the actual logic of fetching authentication challenges
// from the remote registry and updating all credential stores accordingly.
//
// Steps:
// 1. Sends a ping request to the upstream registry to obtain authentication challenges.
// 2. Parses and stores the received challenges.
// 3. Iterates through all credential stores and updates them with the new challenge data.
func (r *AuthChallengeManagerImpl) fetchAndUpdateChallengesInternal(ctx context.Context) error {
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
