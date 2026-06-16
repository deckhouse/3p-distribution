package quota

import (
	"context"
	"testing"

	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"
)

// fakeRepoBlobs is a per-repo blob enumerator/stat backed by an in-memory map.
type fakeRepoBlobs struct {
	sizes map[digest.Digest]int64 // nil size value (missing key) => ErrBlobUnknown
}

func (f fakeRepoBlobs) Enumerate(_ context.Context, fn func(digest.Digest) error) error {
	for d := range f.sizes {
		if err := fn(d); err != nil {
			return err
		}
	}
	return nil
}

func (f fakeRepoBlobs) Stat(_ context.Context, d digest.Digest) (distribution.Descriptor, error) {
	sz, ok := f.sizes[d]
	if !ok || sz < 0 {
		return distribution.Descriptor{}, distribution.ErrBlobUnknown
	}
	return distribution.Descriptor{Digest: d, Size: sz}, nil
}

type fakeRepoLister struct{ repos []string }

func (f fakeRepoLister) Enumerate(_ context.Context, fn func(string) error) error {
	for _, r := range f.repos {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func TestStorageFootprintSumsNamespaceBlobsDistinct(t *testing.T) {
	lister := fakeRepoLister{repos: []string{"team-a/app", "team-a/db", "team-b/api"}}
	repoBlobs := map[string]fakeRepoBlobs{
		"team-a/app": {sizes: map[digest.Digest]int64{"sha256:a": 100, "sha256:shared": 50}},
		"team-a/db":  {sizes: map[digest.Digest]int64{"sha256:b": 200, "sha256:shared": 50}}, // shared counted once
		"team-b/api": {sizes: map[digest.Digest]int64{"sha256:c": 999}},                      // other namespace ignored
	}
	blobsFor := func(_ context.Context, repo string) (RepoBlobs, error) {
		return repoBlobs[repo], nil
	}

	got, err := StorageFootprint(context.Background(), "team-a", lister, blobsFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 100 + 200 + 50 (shared once) = 350
	if got != 350 {
		t.Fatalf("StorageFootprint=%d, want 350", got)
	}
}

func TestStorageFootprintSkipsGCSweptBlobs(t *testing.T) {
	lister := fakeRepoLister{repos: []string{"team-a/app"}}
	// negative size => Stat returns ErrBlobUnknown (already swept by GC)
	repoBlobs := map[string]fakeRepoBlobs{
		"team-a/app": {sizes: map[digest.Digest]int64{"sha256:live": 100, "sha256:swept": -1}},
	}
	blobsFor := func(_ context.Context, repo string) (RepoBlobs, error) { return repoBlobs[repo], nil }

	got, err := StorageFootprint(context.Background(), "team-a", lister, blobsFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 100 {
		t.Fatalf("StorageFootprint=%d, want 100 (swept blob excluded)", got)
	}
}
