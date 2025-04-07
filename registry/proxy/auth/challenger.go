package auth

import (
	"context"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"net/http"
	"net/url"
	"sync"
)

// authChallenger encapsulates a request to the upstream to establish credential challenges
type AuthChallenger interface {
	TryEstablishChallenges(context.Context) error
	ChallengeManager() challenge.Manager
	CredentialStore() auth.CredentialStore
}

func NewRemoteAuthChallenger(params RemoteAuthChallengerParams) *RemoteAuthChallenger {
	return &RemoteAuthChallenger{
		remoteURL:  params.RemoteURL,
		httpClient: params.HttpClient,
		cm:         params.CM,
		cs:         params.CS,
	}
}

type RemoteAuthChallengerParams struct {
	RemoteURL  url.URL
	HttpClient *http.Client
	CM         challenge.Manager
	CS         auth.CredentialStore
}

type RemoteAuthChallenger struct {
	remoteURL  url.URL
	httpClient *http.Client
	cm         challenge.Manager
	cs         auth.CredentialStore
	sync.Mutex
}

func (r *RemoteAuthChallenger) CredentialStore() auth.CredentialStore {
	return r.cs
}

func (r *RemoteAuthChallenger) ChallengeManager() challenge.Manager {
	return r.cm
}

// TryEstablishChallenges will attempt to get a challenge type for the upstream if none currently exist
func (r *RemoteAuthChallenger) TryEstablishChallenges(ctx context.Context) error {
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
	if err := Ping(r.cm, remoteURL.String(), challengeHeader, r.httpClient); err != nil {
		return err
	}

	dcontext.GetLogger(ctx).Infof("Challenge established with upstream : %s %s", remoteURL, r.cm)
	return nil
}
