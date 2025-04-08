package uncached

import (
	"context"

	"github.com/docker/distribution"
	proxy_auth "github.com/docker/distribution/registry/proxy/auth"
)

// proxyTagService supports local and remote lookup of tags.
func NewProxyTagService(params ProxyTagServiceParams) *proxyTagService {
	return &proxyTagService{
		remoteTags:     params.RemoteTags,
		authChallenger: params.AuthChallenger,
	}
}

type ProxyTagServiceParams struct {
	RemoteTags     distribution.TagService
	AuthChallenger proxy_auth.AuthChallenger
}

type proxyTagService struct {
	remoteTags     distribution.TagService
	authChallenger proxy_auth.AuthChallenger
}

var _ distribution.TagService = proxyTagService{}

// Get attempts to get the most recent digest for the tag by checking the remote
// tag service first and then caching it locally.  If the remote is unavailable
// the local association is returned
func (pt proxyTagService) Get(ctx context.Context, tag string) (distribution.Descriptor, error) {
	err := pt.authChallenger.TryEstablishChallenges(ctx)
	if err != nil {
		return distribution.Descriptor{}, err
	}

	desc, err := pt.remoteTags.Get(ctx, tag)
	if err != nil {
		return distribution.Descriptor{}, err
	}
	return desc, nil
}

func (pt proxyTagService) Tag(ctx context.Context, tag string, desc distribution.Descriptor) error {
	return distribution.ErrUnsupported
}

func (pt proxyTagService) Untag(ctx context.Context, tag string) error {
	return distribution.ErrUnsupported
}

func (pt proxyTagService) All(ctx context.Context) ([]string, error) {
	err := pt.authChallenger.TryEstablishChallenges(ctx)
	if err != nil {
		return []string{}, err
	}

	return pt.remoteTags.All(ctx)
}

func (pt proxyTagService) Lookup(ctx context.Context, digest distribution.Descriptor) ([]string, error) {
	return []string{}, distribution.ErrUnsupported
}
