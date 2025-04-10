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

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	"github.com/docker/distribution/configuration"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	proxy_auth "github.com/docker/distribution/registry/proxy/auth"
	manifests_cached "github.com/docker/distribution/registry/proxy/manifests/cached"
	manifests_uncached "github.com/docker/distribution/registry/proxy/manifests/uncached"
	proxy_scheduler "github.com/docker/distribution/registry/proxy/scheduler"
	"github.com/docker/distribution/registry/storage"
	"github.com/docker/distribution/registry/storage/driver"
)

// proxyingRegistry fetches content from a remote registry and caches it locally
type proxyingRegistry struct {
	embedded  distribution.Namespace // provides local registry functionality
	scheduler *proxy_scheduler.TTLExpirationScheduler

	remoteURL     url.URL
	httpTransport *http.Transport

	challengeManager challenge.Manager
	basicAuthCred    auth.CredentialStore
	tokenAuthCred    auth.CredentialStore
	authChallenger   proxy_auth.AuthChallengeManager

	remotePathOnly string
	localPathAlias string
	cacheEnable    bool
}

// NewProxyRegistry creates a proxy registry
func NewProxyRegistry(
	ctx context.Context,
	registry distribution.Namespace,
	driver driver.StorageDriver,
	config configuration.Proxy,
) (
	proxyRegistry distribution.Namespace,
	ttlExpSchedulerRun bool,
	cacheEnable bool,
	err error,
) {
	cacheEnable = !config.Cache.Disabled

	remotePathOnly := strings.Trim(strings.TrimSpace(config.RemotePathOnly), "/")
	localPathAlias := strings.Trim(strings.TrimSpace(config.LocalPathAlias), "/")
	if remotePathOnly == "" && localPathAlias != "" {
		err = fmt.Errorf(
			"invalid configuration: unknown remote path for the alias of the local path '%s'. "+
				"Please specify 'proxy.remotepathonly' field",
			localPathAlias,
		)
		return
	}

	remoteURL, err := url.Parse(config.RemoteURL)
	if err != nil {
		err = fmt.Errorf("failed to parse remote URL '%s': %w", config.RemoteURL, err)
		return
	}

	var scheduler *proxy_scheduler.TTLExpirationScheduler
	if ttl := config.TTL.Duration(); ttl > 0 && cacheEnable {
		vacuum := storage.NewVacuum(ctx, driver)
		scheduler = proxy_scheduler.NewTTLExpirationScheduler(ctx, ttl, driver, registry)
		scheduler.OnBlobExpire(func(ref reference.Reference) error {
			r, ok := ref.(reference.Canonical)
			if !ok {
				return fmt.Errorf("unexpected reference type in OnBlobExpire: %T", ref)
			}

			repo, err := registry.Repository(ctx, r)
			if err != nil {
				return fmt.Errorf("failed to get repository for reference %v: %w", r, err)
			}

			blobs := repo.Blobs(ctx)

			// Clear the repository reference and descriptor caches
			if err := blobs.Delete(ctx, r.Digest()); err != nil {
				return fmt.Errorf("failed to delete blob %v: %w", r.Digest(), err)
			}

			if err := vacuum.RemoveBlob(r.Digest().String()); err != nil {
				return fmt.Errorf("failed to remove blob %v from vacuum: %w", r.Digest(), err)
			}

			return nil
		})

		scheduler.OnManifestExpire(func(ref reference.Reference) error {
			r, ok := ref.(reference.Canonical)
			if !ok {
				return fmt.Errorf("unexpected reference type in OnManifestExpire: %T", ref)
			}

			repo, err := registry.Repository(ctx, r)
			if err != nil {
				return fmt.Errorf("failed to get repository for manifest reference %v: %w", r, err)
			}

			manifests, err := repo.Manifests(ctx)
			if err != nil {
				return fmt.Errorf("failed to get manifests for reference %v: %w", r, err)
			}

			if err := manifests.Delete(ctx, r.Digest()); err != nil {
				return fmt.Errorf("failed to delete manifest %v: %w", r.Digest(), err)
			}

			return nil
		})

		if err = scheduler.Start(); err != nil {
			err = fmt.Errorf("failed to start TTL expiration scheduler: %w", err)
			return
		}
		ttlExpSchedulerRun = true
	}

	// Http transport
	var tlsConfig *tls.Config
	if config.CA != nil {
		var CARaw []byte
		CAPath := *config.CA
		CARaw, err = os.ReadFile(CAPath)
		if err != nil {
			err = fmt.Errorf("failed to read the CA file at %v: %w", CAPath, err)
			return
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(CARaw) {
			err = fmt.Errorf("failed to add CA file %v to the cert pool", CAPath)
			return
		}
		tlsConfig = &tls.Config{
			RootCAs: certPool,
		}
	}
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = tlsConfig

	// Auth
	challengeManager := challenge.NewSimpleManager()
	basicAuthCred := proxy_auth.NewBasicAuthCredentials(config.Username, config.Password, remoteURL.String())
	tokenAuthCred := proxy_auth.NewTokenAuthCredentials(config.Username, config.Password, remoteURL.String())
	authChallenger := proxy_auth.NewAuthChallengeManager(
		proxy_auth.AuthChallengeManagerParams{
			RemoteURL: *remoteURL,
			HttpClient: &http.Client{
				Transport: httpTransport,
			},
			CredentialStores: []proxy_auth.CredentialStore{tokenAuthCred, basicAuthCred},
			ChallengeManager: challengeManager,
		},
	)

	proxyRegistry = &proxyingRegistry{
		embedded:         registry,
		scheduler:        scheduler,
		remoteURL:        *remoteURL,
		httpTransport:    httpTransport,
		remotePathOnly:   remotePathOnly,
		localPathAlias:   localPathAlias,
		cacheEnable:      cacheEnable,
		challengeManager: challengeManager,
		basicAuthCred:    basicAuthCred,
		tokenAuthCred:    tokenAuthCred,
		authChallenger:   authChallenger,
	}
	return
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

	tr := transport.NewTransport(pr.httpTransport,
		auth.NewAuthorizer(
			// Common challenger manager
			pr.challengeManager,

			// Token Handler
			auth.NewTokenHandlerWithOptions(
				auth.TokenHandlerOptions{
					Transport:   pr.httpTransport,
					Credentials: pr.tokenAuthCred,
					Scopes: []auth.Scope{
						auth.RepositoryScope{
							Repository: remoteRepositoryName.Name(),
							Actions:    []string{"pull"},
						},
					},
					Logger: dcontext.GetLogger(ctx),
				}),

			// Basic Handler
			auth.NewBasicHandler(pr.basicAuthCred),
		),
	)

	if err := pr.authChallenger.FetchAndUpdateChallenges(ctx); err != nil {
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

	if !pr.cacheEnable {
		return &proxiedRepository{
			blobStore: manifests_uncached.NewProxyBlobStore(
				manifests_uncached.ProxyBlobStoreParams{
					RemoteStore:          remoteRepo.Blobs(ctx),
					RemoteRepositoryName: remoteRepositoryName,
					AuthChallenger:       pr.authChallenger,
				},
			),
			manifests: manifests_uncached.NewProxyManifestStore(
				manifests_uncached.ProxyManifestStoreParams{
					RemoteRepositoryName: remoteRepositoryName,
					RemoteManifests:      remoteManifests,
					Ctx:                  ctx,
					AuthChallenger:       pr.authChallenger,
				}),
			localRepositoryName: localRepositoryName,
			tags: manifests_uncached.NewProxyTagService(
				manifests_uncached.ProxyTagServiceParams{
					RemoteTags:     remoteRepo.Tags(ctx),
					AuthChallenger: pr.authChallenger,
				}),
		}, nil
	}

	localRepo, err := pr.embedded.Repository(ctx, localRepositoryName)
	if err != nil {
		return nil, err
	}
	localManifests, err := localRepo.Manifests(ctx, storage.SkipLayerVerification())
	if err != nil {
		return nil, err
	}

	return &proxiedRepository{
		blobStore: manifests_cached.NewProxyBlobStore(
			manifests_cached.ProxyBlobStoreParams{
				LocalStore:           localRepo.Blobs(ctx),
				RemoteStore:          remoteRepo.Blobs(ctx),
				Scheduler:            pr.scheduler,
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
