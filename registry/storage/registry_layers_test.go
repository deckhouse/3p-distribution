package storage

import (
	"context"
	"io"
	"testing"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	"github.com/docker/distribution/registry/storage/cache/memory"
	"github.com/docker/distribution/registry/storage/driver/testdriver"
	"github.com/docker/distribution/testutil"
	"github.com/opencontainers/go-digest"
)

// TestEnumerateLayerLinksIncludesOrphans verifies that EnumerateLayerLinks
// returns blobs linked under a repository's _layers even when no manifest
// references them — i.e. the physical footprint used for quota accounting.
func TestEnumerateLayerLinksIncludesOrphans(t *testing.T) {
	ctx := context.Background()
	imageName, _ := reference.WithName("team-a/app")
	driver := testdriver.New()
	registry, err := NewRegistry(ctx, driver, BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider()), EnableDelete, EnableRedirect)
	if err != nil {
		t.Fatalf("error creating registry: %v", err)
	}
	repository, err := registry.Repository(ctx, imageName)
	if err != nil {
		t.Fatalf("unexpected error getting repo: %v", err)
	}
	bs := repository.Blobs(ctx)

	// Upload two distinct blobs and commit them as layer links. No manifest
	// references them, so they are "orphans".
	want := map[digest.Digest]bool{}
	for i := 0; i < 2; i++ {
		rd, dgst, err := testutil.CreateRandomTarFile()
		if err != nil {
			t.Fatalf("error creating random blob: %v", err)
		}
		wr, err := bs.Create(ctx)
		if err != nil {
			t.Fatalf("error starting blob upload: %v", err)
		}
		if _, err := io.Copy(wr, rd); err != nil {
			t.Fatalf("error copying blob data: %v", err)
		}
		if _, err := wr.Commit(ctx, distribution.Descriptor{Digest: dgst}); err != nil {
			t.Fatalf("error committing blob: %v", err)
		}
		want[dgst] = true
	}

	le, ok := repository.(interface {
		EnumerateLayerLinks(context.Context, func(digest.Digest) error) error
	})
	if !ok {
		t.Fatal("repository does not implement EnumerateLayerLinks")
	}

	got := map[digest.Digest]bool{}
	if err := le.EnumerateLayerLinks(ctx, func(d digest.Digest) error {
		got[d] = true
		return nil
	}); err != nil {
		t.Fatalf("EnumerateLayerLinks: %v", err)
	}

	for d := range want {
		if !got[d] {
			t.Fatalf("orphan blob %s not returned by EnumerateLayerLinks (got %d blobs)", d, len(got))
		}
	}
}
