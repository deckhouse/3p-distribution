package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	"github.com/docker/distribution/configuration"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/distribution/registry/storage"
	"github.com/docker/distribution/registry/storage/driver"
	proxy_auth "github.com/docker/distribution/registry/proxy/auth"
	manifests_cached "github.com/docker/distribution/registry/proxy/manifests/cached"
	proxy_scheduler "github.com/docker/distribution/registry/proxy/scheduler"
)

var repositoryTTL = 24 * 7 * time.Hour

// proxyingRegistry fetches content from a remote registry and caches it locally
type proxyingRegistry struct {
	embedded       distribution.Namespace // provides local registry functionality
	scheduler      *proxy_scheduler.TTLExpirationScheduler
	ttl            *time.Duration
	remoteURL      url.URL
	httpClient     *http.Client
	httpTransport  *http.Transport
	authChallenger proxy_auth.AuthChallenger
	remotePathOnly string
	localPathAlias string
}

// NewRegistryPullThroughCache creates a registry acting as a pull through cache
func NewRegistryPullThroughCache(ctx context.Context, registry distribution.Namespace, driver driver.StorageDriver, config configuration.Proxy) (distribution.Namespace, error) {
	remotePathOnly := strings.Trim(strings.TrimSpace(config.RemotePathOnly), "/")
	localPathAlias := strings.Trim(strings.TrimSpace(config.LocalPathAlias), "/")

	if remotePathOnly == "" && localPathAlias != "" {
		return nil, fmt.Errorf(
			"unknown remote path for the alias of the local path '%s', fill in the 'proxy.remotepathonly' field",
			localPathAlias,
		)
	}

	remoteURL, err := url.Parse(config.RemoteURL)
	if err != nil {
		return nil, err
	}

	var scheduler *proxy_scheduler.TTLExpirationScheduler
	var ttl *time.Duration
	if config.TTL == nil {
		// Default TTL is 7 days
		ttl = &repositoryTTL
	} else if *config.TTL > 0 {
		ttl = config.TTL
	} else {
		// TTL is disabled, never expire
		ttl = nil
	}

	if ttl != nil {
		vacuum := storage.NewVacuum(ctx, driver)
		scheduler = proxy_scheduler.New(ctx, *ttl, driver, registry, "/scheduler-state.json")
		scheduler.OnBlobExpire(func(ref reference.Reference) error {
			var r reference.Canonical
			var ok bool
			if r, ok = ref.(reference.Canonical); !ok {
				return fmt.Errorf("unexpected reference type : %T", ref)
			}

			repo, err := registry.Repository(ctx, r)
			if err != nil {
				return err
			}

			blobs := repo.Blobs(ctx)

			// Clear the repository reference and descriptor caches
			err = blobs.Delete(ctx, r.Digest())
			if err != nil {
				return err
			}

			err = vacuum.RemoveBlob(r.Digest().String())
			if err != nil {
				return err
			}

			return nil
		})

		scheduler.OnManifestExpire(func(ref reference.Reference) error {
			var r reference.Canonical
			var ok bool
			if r, ok = ref.(reference.Canonical); !ok {
				return fmt.Errorf("unexpected reference type : %T", ref)
			}

			repo, err := registry.Repository(ctx, r)
			if err != nil {
				return err
			}

			manifests, err := repo.Manifests(ctx)
			if err != nil {
				return err
			}
			err = manifests.Delete(ctx, r.Digest())
			if err != nil {
				return err
			}
			return nil
		})

		err = scheduler.Start()
		if err != nil {
			return nil, err
		}
	}

	var tlsConfig *tls.Config
	if config.CA != nil {
		caPath := *config.CA
		ca, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read the CA file at %v: %w", caPath, err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("failed to add the CA file to the cert pool %v", caPath)
		}
		tlsConfig = &tls.Config{
			RootCAs: certPool,
		}
	}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = tlsConfig
	httpClient := &http.Client{
		Transport: httpTransport,
	}

	cs, err := proxy_auth.ConfigureAuth(config.Username, config.Password, config.RemoteURL, httpClient)
	if err != nil {
		return nil, err
	}

	return &proxyingRegistry{
		embedded:       registry,
		scheduler:      scheduler,
		ttl:            ttl,
		remoteURL:      *remoteURL,
		httpClient:     httpClient,
		httpTransport:  httpTransport,
		remotePathOnly: remotePathOnly,
		localPathAlias: localPathAlias,
		authChallenger: proxy_auth.NewRemoteAuthChallenger(
			proxy_auth.RemoteAuthChallengerParams{
				RemoteURL:  *remoteURL,
				HttpClient: httpClient,
				CM:         challenge.NewSimpleManager(),
				CS:         cs,
			}),
	}, nil
}

func (pr *proxyingRegistry) Scope() distribution.Scope {
	return distribution.GlobalScope
}

func (pr *proxyingRegistry) Repositories(ctx context.Context, repos []string, last string) (n int, err error) {
	return pr.embedded.Repositories(ctx, repos, last)
}

func (pr *proxyingRegistry) Repository(ctx context.Context, name reference.Named) (distribution.Repository, error) {
	localRepositoryName := name
	remoteRepositoryName, err := pr.getRemoteRepositoryName(name)
	if err != nil {
		return nil, err
	}

	if _, err = pr.repositoryIsAllowed(name); err != nil {
		return nil, err
	}

	c := pr.authChallenger

	tkopts := auth.TokenHandlerOptions{
		Transport:   pr.httpTransport,
		Credentials: c.CredentialStore(),
		Scopes: []auth.Scope{
			auth.RepositoryScope{
				Repository: remoteRepositoryName.Name(),
				Actions:    []string{"pull"},
			},
		},
		Logger: dcontext.GetLogger(ctx),
	}

	tr := transport.NewTransport(pr.httpTransport,
		auth.NewAuthorizer(c.ChallengeManager(),
			auth.NewTokenHandlerWithOptions(tkopts)))

	localRepo, err := pr.embedded.Repository(ctx, localRepositoryName)
	if err != nil {
		return nil, err
	}
	localManifests, err := localRepo.Manifests(ctx, storage.SkipLayerVerification())
	if err != nil {
		return nil, err
	}

	remoteRepo, err := client.NewRepository(remoteRepositoryName, pr.remoteURL.String(), tr)
	if err != nil {
		return nil, err
	}

	remoteManifests, err := remoteRepo.Manifests(ctx)
	if err != nil {
		return nil, err
	}

	return &proxiedRepository{
		blobStore: manifests_cached.NewProxyBlobStore(
			manifests_cached.ProxyBlobStoreParams{
				LocalStore:           localRepo.Blobs(ctx),
				RemoteStore:          remoteRepo.Blobs(ctx),
				Scheduler:            pr.scheduler,
				TTL:                  pr.ttl,
				LocalRepositoryName:  localRepositoryName,
				RemoteRepositoryName: remoteRepositoryName,
				AuthChallenger:       pr.authChallenger,
			},
		),
		manifests: manifests_cached.NewProxyManifestStore(
			manifests_cached.ProxyManifestStoreParams{
				LocalRepositoryName:  localRepositoryName,
				RemoteRepositoryName: remoteRepositoryName,
				LocalManifests:       localManifests, // Options?
				RemoteManifests:      remoteManifests,
				Ctx:                  ctx,
				Scheduler:            pr.scheduler,
				TTL:                  pr.ttl,
				AuthChallenger:       pr.authChallenger,
			}),
		localRepositoryName: localRepositoryName,
		tags: manifests_cached.NewProxyTagService(
			manifests_cached.ProxyTagServiceParams{
				LocalTags:      localRepo.Tags(ctx),
				RemoteTags:     remoteRepo.Tags(ctx),
				AuthChallenger: pr.authChallenger,
			}),
	}, nil
}

func (pr *proxyingRegistry) Blobs() distribution.BlobEnumerator {
	return pr.embedded.Blobs()
}

func (pr *proxyingRegistry) BlobStatter() distribution.BlobStatter {
	return pr.embedded.BlobStatter()
}

func (pr *proxyingRegistry) getRemoteRepositoryName(name reference.Named) (reference.Named, error) {
	repoName := name.String()

	// If localPathAlias is empty, no changes to the remote repository
	if pr.localPathAlias == "" {
		return name, nil
	}

	// If localPathAlias is not empty, replace it with remotePathOnly
	if strings.HasPrefix(repoName, pr.localPathAlias) {
		newRepoName := pr.remotePathOnly + strings.TrimPrefix(repoName, pr.localPathAlias)
		remoteRepositoryName, err := reference.WithName(newRepoName)
		if err != nil {
			return nil, distribution.ErrRepositoryNameInvalid{
				Name:   newRepoName,
				Reason: err,
			}
		}
		return remoteRepositoryName, nil
	}

	return name, nil
}

func (pr *proxyingRegistry) repositoryIsAllowed(name reference.Named) (bool, error) {
	// Skip if remotePathOnly is empty
	if pr.remotePathOnly == "" {
		return true, nil
	}

	repoName := name.String()
	allowedPrefix := pr.remotePathOnly

	// If localPathAlias is not empty, use it as the prefix
	if pr.localPathAlias != "" {
		allowedPrefix = pr.localPathAlias
	}

	// Check if the repository name has the allowed prefix
	if !strings.HasPrefix(repoName, allowedPrefix) {
		return false, distribution.ErrRepositoryUnknownWithReason{
			Name: repoName,
			Reason: fmt.Errorf(
				"allowed prefix is '%s'",
				allowedPrefix,
			),
		}
	}
	return true, nil
}

// proxiedRepository uses proxying blob and manifest services to serve content
// locally, or pulling it through from a remote and caching it locally if it doesn't
// already exist
type proxiedRepository struct {
	blobStore           distribution.BlobStore
	manifests           distribution.ManifestService
	localRepositoryName reference.Named
	tags                distribution.TagService
}

func (pr *proxiedRepository) Manifests(ctx context.Context, options ...distribution.ManifestServiceOption) (distribution.ManifestService, error) {
	return pr.manifests, nil
}

func (pr *proxiedRepository) Blobs(ctx context.Context) distribution.BlobStore {
	return pr.blobStore
}

func (pr *proxiedRepository) Named() reference.Named {
	return pr.localRepositoryName
}

func (pr *proxiedRepository) Tags(ctx context.Context) distribution.TagService {
	return pr.tags
}
