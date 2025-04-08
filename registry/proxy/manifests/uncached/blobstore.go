package uncached

import (
	"context"
	"io"
	"net/http"
	"strconv"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	proxy_auth "github.com/docker/distribution/registry/proxy/auth"
	proxy_metrics "github.com/docker/distribution/registry/proxy/metrics"
	"github.com/opencontainers/go-digest"
)

func NewProxyBlobStore(params ProxyBlobStoreParams) *proxyBlobStore {
	return &proxyBlobStore{
		remoteStore:          params.RemoteStore,
		remoteRepositoryName: params.RemoteRepositoryName,
		authChallenger:       params.AuthChallenger,
	}
}

type ProxyBlobStoreParams struct {
	RemoteStore          distribution.BlobService
	RemoteRepositoryName reference.Named
	AuthChallenger       proxy_auth.AuthChallenger
}

type proxyBlobStore struct {
	remoteStore          distribution.BlobService
	remoteRepositoryName reference.Named
	authChallenger       proxy_auth.AuthChallenger
}

var _ distribution.BlobStore = &proxyBlobStore{}

func setResponseHeaders(w http.ResponseWriter, length int64, mediaType string, digest digest.Digest) {
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", digest.String())
	w.Header().Set("Etag", digest.String())
}

func (pbs *proxyBlobStore) copyContent(ctx context.Context, dgst digest.Digest, writer io.Writer) (distribution.Descriptor, error) {
	desc, err := pbs.remoteStore.Stat(ctx, dgst)
	if err != nil {
		return distribution.Descriptor{}, err
	}

	if w, ok := writer.(http.ResponseWriter); ok {
		setResponseHeaders(w, desc.Size, desc.MediaType, dgst)
	}

	remoteReader, err := pbs.remoteStore.Open(ctx, dgst)
	if err != nil {
		return distribution.Descriptor{}, err
	}

	defer remoteReader.Close()

	_, err = io.CopyN(writer, remoteReader, desc.Size)
	if err != nil {
		return distribution.Descriptor{}, err
	}

	proxy_metrics.ProxyMetrics.BlobPush(uint64(desc.Size))

	return desc, nil
}

func (pbs *proxyBlobStore) ServeBlob(ctx context.Context, w http.ResponseWriter, r *http.Request, dgst digest.Digest) error {
	if err := pbs.authChallenger.TryEstablishChallenges(ctx); err != nil {
		return err
	}
	_, err := pbs.copyContent(ctx, dgst, w)
	return err
}

func (pbs *proxyBlobStore) Stat(ctx context.Context, dgst digest.Digest) (distribution.Descriptor, error) {
	if err := pbs.authChallenger.TryEstablishChallenges(ctx); err != nil {
		return distribution.Descriptor{}, err
	}

	return pbs.remoteStore.Stat(ctx, dgst)
}

func (pbs *proxyBlobStore) Get(ctx context.Context, dgst digest.Digest) ([]byte, error) {
	if err := pbs.authChallenger.TryEstablishChallenges(ctx); err != nil {
		return []byte{}, err
	}

	return pbs.remoteStore.Get(ctx, dgst)
}

// Unsupported functions
func (pbs *proxyBlobStore) Put(ctx context.Context, mediaType string, p []byte) (distribution.Descriptor, error) {
	return distribution.Descriptor{}, distribution.ErrUnsupported
}

func (pbs *proxyBlobStore) Create(ctx context.Context, options ...distribution.BlobCreateOption) (distribution.BlobWriter, error) {
	return nil, distribution.ErrUnsupported
}

func (pbs *proxyBlobStore) Resume(ctx context.Context, id string) (distribution.BlobWriter, error) {
	return nil, distribution.ErrUnsupported
}

func (pbs *proxyBlobStore) Mount(ctx context.Context, sourceRepo reference.Named, dgst digest.Digest) (distribution.Descriptor, error) {
	return distribution.Descriptor{}, distribution.ErrUnsupported
}

func (pbs *proxyBlobStore) Open(ctx context.Context, dgst digest.Digest) (io.ReadSeekCloser, error) {
	return nil, distribution.ErrUnsupported
}

func (pbs *proxyBlobStore) Delete(ctx context.Context, dgst digest.Digest) error {
	return distribution.ErrUnsupported
}
