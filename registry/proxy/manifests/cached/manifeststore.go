package cached

import (
	"context"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	dcontext "github.com/docker/distribution/context"
	proxy_auth "github.com/docker/distribution/registry/proxy/auth"
	proxy_metrics "github.com/docker/distribution/registry/proxy/metrics"
	proxy_scheduler "github.com/docker/distribution/registry/proxy/scheduler"
	"github.com/opencontainers/go-digest"
)

func NewProxyManifestStore(params ProxyManifestStoreParams) *proxyManifestStore {
	return &proxyManifestStore{
		ctx:                  params.Ctx,
		localManifests:       params.LocalManifests,
		remoteManifests:      params.RemoteManifests,
		localRepositoryName:  params.LocalRepositoryName,
		remoteRepositoryName: params.RemoteRepositoryName,
		scheduler:            params.Scheduler,
		authChallenger:       params.AuthChallenger,
	}
}

type ProxyManifestStoreParams struct {
	Ctx                  context.Context
	LocalManifests       distribution.ManifestService
	RemoteManifests      distribution.ManifestService
	LocalRepositoryName  reference.Named
	RemoteRepositoryName reference.Named
	Scheduler            *proxy_scheduler.TTLExpirationScheduler
	AuthChallenger       proxy_auth.AuthChallengeManager
}

type proxyManifestStore struct {
	ctx                  context.Context
	localManifests       distribution.ManifestService
	remoteManifests      distribution.ManifestService
	localRepositoryName  reference.Named
	remoteRepositoryName reference.Named
	scheduler            *proxy_scheduler.TTLExpirationScheduler
	authChallenger       proxy_auth.AuthChallengeManager
}

var _ distribution.ManifestService = &proxyManifestStore{}

func (pms proxyManifestStore) Exists(ctx context.Context, dgst digest.Digest) (bool, error) {
	exists, err := pms.localManifests.Exists(ctx, dgst)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	if err := pms.authChallenger.FetchAndUpdateChallenges(ctx); err != nil {
		return false, err
	}
	return pms.remoteManifests.Exists(ctx, dgst)
}

func (pms proxyManifestStore) Get(ctx context.Context, dgst digest.Digest, options ...distribution.ManifestServiceOption) (distribution.Manifest, error) {
	// At this point `dgst` was either specified explicitly, or returned by the
	// tagstore with the most recent association.
	var fromRemote bool
	manifest, err := pms.localManifests.Get(ctx, dgst, options...)
	if err != nil {
		if err := pms.authChallenger.FetchAndUpdateChallenges(ctx); err != nil {
			return nil, err
		}

		manifest, err = pms.remoteManifests.Get(ctx, dgst, options...)
		if err != nil {
			return nil, err
		}
		fromRemote = true
	}

	_, payload, err := manifest.Payload()
	if err != nil {
		return nil, err
	}

	proxy_metrics.ProxyMetrics.ManifestPush(uint64(len(payload)))
	if fromRemote {
		proxy_metrics.ProxyMetrics.ManifestPull(uint64(len(payload)))

		_, err = pms.localManifests.Put(ctx, manifest)
		if err != nil {
			return nil, err
		}

		// Schedule the manifest blob for removal
		repoBlob, err := reference.WithDigest(pms.localRepositoryName, dgst)
		if err != nil {
			dcontext.GetLogger(ctx).Errorf("Error creating reference: %s", err)
			return nil, err
		}

		if pms.scheduler != nil {
			if err := pms.scheduler.AddManifest(repoBlob); err != nil {
				dcontext.GetLogger(ctx).Errorf("Error adding manifest: %s", err)
			}
		}
		// Ensure the manifest blob is cleaned up
		//pms.scheduler.AddBlob(blobRef, repositoryTTL)
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
