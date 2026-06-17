package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	"github.com/docker/distribution/configuration"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/quota"
	"github.com/opencontainers/go-digest"
)

// namespaceOf returns the first path segment of a repository name (the project /
// Kubernetes namespace the repository is bound to).
func namespaceOf(repo string) string {
	if i := strings.IndexByte(repo, '/'); i >= 0 {
		return repo[:i]
	}
	return repo
}

const quotaHTTPTimeout = 10 * time.Second

var quotaErrorGroup = "payload-registry.quota"

// ErrorCodeQuotaExceeded is returned (HTTP 413) when a blob upload would exceed
// the project's storage quota.
var ErrorCodeQuotaExceeded = errcode.Register(quotaErrorGroup, errcode.ErrorDescriptor{
	Value:          "QUOTA_EXCEEDED",
	Message:        "project storage quota exceeded",
	Description:    "The upload was rejected because it would exceed the project's storage quota.",
	HTTPStatusCode: http.StatusRequestEntityTooLarge,
})

// ErrorCodeQuotaUnavailable is returned (HTTP 503) when the quota could not be
// evaluated; the client should retry.
var ErrorCodeQuotaUnavailable = errcode.Register(quotaErrorGroup, errcode.ErrorDescriptor{
	Value:          "QUOTA_UNAVAILABLE",
	Message:        "project storage quota could not be evaluated",
	Description:    "The quota service was unavailable; the upload was rejected (fail-closed). Retry later.",
	HTTPStatusCode: http.StatusServiceUnavailable,
})

// newQuotaEnforcer builds a quota.Enforcer from config: an HTTP limit client
// targeting the apiserver and a footprint provider backed by the registry.
func newQuotaEnforcer(cfg configuration.Quota, registry distribution.Namespace) (*quota.Enforcer, error) {
	httpClient, err := quotaHTTPClient(cfg.CA)
	if err != nil {
		return nil, err
	}
	limits := quota.NewLimitClient(cfg.Endpoint, httpClient)
	return quota.NewEnforcer(limits, registryFootprint{registry: registry}), nil
}

func quotaHTTPClient(caPath string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read quota CA %q: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in quota CA %q", caPath)
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{
		Timeout:   quotaHTTPTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

// registryFootprint adapts a distribution.Namespace to a quota.FootprintProvider
// by enumerating the namespace's repositories and their blobs.
type registryFootprint struct {
	registry distribution.Namespace
}

func (rf registryFootprint) Footprint(ctx context.Context, namespace string) (int64, error) {
	enumerator, ok := rf.registry.(distribution.RepositoryEnumerator)
	if !ok {
		return 0, fmt.Errorf("registry does not support repository enumeration")
	}

	blobsFor := func(ctx context.Context, repo string) (quota.RepoBlobs, error) {
		named, err := reference.WithName(repo)
		if err != nil {
			return nil, fmt.Errorf("parse repository %q: %w", repo, err)
		}
		r, err := rf.registry.Repository(ctx, named)
		if err != nil {
			return nil, fmt.Errorf("open repository %q: %w", repo, err)
		}
		return layerRepoBlobs{repo: r}, nil
	}

	return quota.StorageFootprint(ctx, namespace, enumerator, blobsFor)
}

// layerEnumerator is implemented by the storage repository to enumerate the
// blobs physically linked under a repository's `_layers` (including orphans).
type layerEnumerator interface {
	EnumerateLayerLinks(ctx context.Context, fn func(dgst digest.Digest) error) error
}

// layerRepoBlobs yields a repository's physical blob footprint: every blob
// linked under `_layers` (referenced or orphaned, until GC reclaims it). This is
// what defeats the push-then-delete-manifests evasion — deleting manifests does
// not drop usage until GC removes the layer links.
type layerRepoBlobs struct {
	repo distribution.Repository
}

func (l layerRepoBlobs) Enumerate(ctx context.Context, fn func(dgst digest.Digest) error) error {
	le, ok := l.repo.(layerEnumerator)
	if !ok {
		return fmt.Errorf("repository does not support layer enumeration")
	}
	return le.EnumerateLayerLinks(ctx, fn)
}

func (l layerRepoBlobs) Stat(ctx context.Context, dgst digest.Digest) (distribution.Descriptor, error) {
	return l.repo.Blobs(ctx).Stat(ctx, dgst)
}
