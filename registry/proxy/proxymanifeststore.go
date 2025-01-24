package proxy

import (
	"context"

	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"
)

type proxyManifestStore struct {
	ctx             context.Context
	remoteManifests distribution.ManifestService
	authChallenger  authChallenger
}

var _ distribution.ManifestService = &proxyManifestStore{}

func (pms proxyManifestStore) Exists(ctx context.Context, dgst digest.Digest) (bool, error) {
	if err := pms.authChallenger.tryEstablishChallenges(ctx); err != nil {
		return false, err
	}
	return pms.remoteManifests.Exists(ctx, dgst)
}

func (pms proxyManifestStore) Get(ctx context.Context, dgst digest.Digest, options ...distribution.ManifestServiceOption) (distribution.Manifest, error) {
	// At this point `dgst` was either specified explicitly, or returned by the
	// tagstore with the most recent association.

	if err := pms.authChallenger.tryEstablishChallenges(ctx); err != nil {
		return nil, err
	}

	manifest, err := pms.remoteManifests.Get(ctx, dgst, options...)
	if err != nil {
		return nil, err
	}

	return manifest, err
}

func (pms proxyManifestStore) Put(ctx context.Context, manifest distribution.Manifest, options ...distribution.ManifestServiceOption) (digest.Digest, error) {
	var d digest.Digest
	return d, distribution.ErrUnsupported
}

func (pms proxyManifestStore) Delete(ctx context.Context, dgst digest.Digest) error {
	return distribution.ErrUnsupported
}
