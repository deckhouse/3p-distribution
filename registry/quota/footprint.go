package quota

import (
	"context"
	"errors"
	"strings"

	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"
)

// RepoLister enumerates repository names in the registry (the storage
// RepositoryEnumerator).
type RepoLister interface {
	Enumerate(ctx context.Context, fn func(repo string) error) error
}

// RepoBlobs enumerates and stats the blobs linked under a single repository
// (the per-repository linked blob store).
type RepoBlobs interface {
	Enumerate(ctx context.Context, fn func(dgst digest.Digest) error) error
	Stat(ctx context.Context, dgst digest.Digest) (distribution.Descriptor, error)
}

// BlobsForRepo returns the blob enumerator/stat for a repository.
type BlobsForRepo func(ctx context.Context, repo string) (RepoBlobs, error)

// StorageFootprint computes the physical footprint (in bytes) of a project: the
// sum of the sizes of the distinct blobs linked under the namespace's
// repositories that still exist in storage. Blobs already reclaimed by GC return
// ErrBlobUnknown from Stat and are skipped, so the footprint drops as GC runs.
func StorageFootprint(ctx context.Context, namespace string, repos RepoLister, blobsFor BlobsForRepo) (int64, error) {
	seen := make(map[digest.Digest]int64)

	err := repos.Enumerate(ctx, func(repo string) error {
		if repo != namespace && !strings.HasPrefix(repo, namespace+"/") {
			return nil
		}
		rb, err := blobsFor(ctx, repo)
		if err != nil {
			return err
		}
		return rb.Enumerate(ctx, func(dgst digest.Digest) error {
			if _, ok := seen[dgst]; ok {
				return nil
			}
			desc, err := rb.Stat(ctx, dgst)
			if err != nil {
				if errors.Is(err, distribution.ErrBlobUnknown) {
					return nil // already reclaimed by GC
				}
				return err
			}
			seen[dgst] = desc.Size
			return nil
		})
	})
	if err != nil {
		return 0, err
	}

	var total int64
	for _, sz := range seen {
		total += sz
	}
	return total, nil
}
