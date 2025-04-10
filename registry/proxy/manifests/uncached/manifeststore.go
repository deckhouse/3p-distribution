package uncached

import (
	"context"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	proxy_auth "github.com/docker/distribution/registry/proxy/auth"
	proxy_metrics "github.com/docker/distribution/registry/proxy/metrics"
	"github.com/opencontainers/go-digest"
)

func NewProxyManifestStore(params ProxyManifestStoreParams) *proxyManifestStore {
	return &proxyManifestStore{
		ctx:                  params.Ctx,
		remoteManifests:      params.RemoteManifests,
		remoteRepositoryName: params.RemoteRepositoryName,
		authChallenger:       params.AuthChallenger,
	}
}

type ProxyManifestStoreParams struct {
	Ctx                  context.Context
	RemoteManifests      distribution.ManifestService
	RemoteRepositoryName reference.Named
	AuthChallenger       proxy_auth.AuthChallengeManager
}

type proxyManifestStore struct {
	ctx                  context.Context
	remoteManifests      distribution.ManifestService
	remoteRepositoryName reference.Named
	authChallenger       proxy_auth.AuthChallengeManager
}

var _ distribution.ManifestService = &proxyManifestStore{}

func (pms proxyManifestStore) Exists(ctx context.Context, dgst digest.Digest) (bool, error) {
	if err := pms.authChallenger.FetchAndUpdateChallenges(ctx); err != nil {
		return false, err
	}
	return pms.remoteManifests.Exists(ctx, dgst)
}

func (pms proxyManifestStore) Get(ctx context.Context, dgst digest.Digest, options ...distribution.ManifestServiceOption) (distribution.Manifest, error) {
	// At this point `dgst` was either specified explicitly, or returned by the
	// tagstore with the most recent association.
	manifest, err := pms.remoteManifests.Get(ctx, dgst, options...)
	if err != nil {
		return nil, err
	}

	_, payload, err := manifest.Payload()
	if err != nil {
		return nil, err
	}

	proxy_metrics.ProxyMetrics.ManifestPush(uint64(len(payload)))
	return manifest, err
}

func (pms proxyManifestStore) Put(ctx context.Context, manifest distribution.Manifest, options ...distribution.ManifestServiceOption) (digest.Digest, error) {
	var d digest.Digest
	return d, distribution.ErrUnsupported
}

func (pms proxyManifestStore) Delete(ctx context.Context, dgst digest.Digest) error {
	return distribution.ErrUnsupported
}
