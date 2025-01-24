package proxy

import (
	"context"

	"github.com/docker/distribution"
	dcontext "github.com/docker/distribution/context"
)

// proxyTagService supports local and remote lookup of tags.
type proxyTagService struct {
	remoteTags     distribution.TagService
	authChallenger authChallenger
}

var _ distribution.TagService = proxyTagService{}

// Get attempts to get the most recent digest for the tag by checking the remote
// tag service first and then caching it locally.  If the remote is unavailable
// the local association is returned
func (pt proxyTagService) Get(ctx context.Context, tag string) (distribution.Descriptor, error) {
	if err := pt.authChallenger.tryEstablishChallenges(ctx); err != nil {
		return distribution.Descriptor{}, err
	}

	desc, err := pt.remoteTags.Get(ctx, tag)
	if err != nil {
		dcontext.GetLogger(ctx).WithError(err).Warningln("Remote tags error, returning not found")
		return distribution.Descriptor{}, distribution.ErrTagUnknown{Tag: tag}
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
	if err := pt.authChallenger.tryEstablishChallenges(ctx); err != nil {
		return []string{}, err
	}

	tags, err := pt.remoteTags.All(ctx)
	if err != nil {
		return []string{}, err
	}

	return tags, err
}

func (pt proxyTagService) Lookup(ctx context.Context, digest distribution.Descriptor) ([]string, error) {
	return []string{}, distribution.ErrUnsupported
}
