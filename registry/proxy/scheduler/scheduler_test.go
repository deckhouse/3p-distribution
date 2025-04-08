package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	distribution_context "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/storage"
	"github.com/docker/distribution/registry/storage/cache/memory"
	storagedriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/libtrust"

	// "github.com/docker/distribution/registry/storage/driver/filesystem"
	"io"

	"github.com/docker/distribution/manifest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/registry/storage/driver/inmemory"
	"github.com/docker/distribution/testutil"
)

type schedulerEntryTest struct {
	EntryType int `json:"EntryType"`
}

func newRegistry(t *testing.T) (storagedriver.StorageDriver, distribution.Namespace) {
	ctx := distribution_context.Background()
	k, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	localDriver := inmemory.New()
	localRegistry, err := storage.NewRegistry(ctx, localDriver, storage.BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider()), storage.EnableRedirect, storage.DisableDigestResumption, storage.Schema1SigningKey(k), storage.EnableSchema1)
	if err != nil {
		t.Fatalf("error creating registry: %v", err)
	}
	return localDriver, localRegistry
}

func populateRepo(ctx context.Context, t *testing.T, registry distribution.Namespace, repoName, tag string, blobsCount int) (reference.Canonical, []reference.Canonical) {
	blobsRefs := make([]reference.Canonical, 0, blobsCount)

	// Manifest that will contain information about the layers (blobs)
	m := schema1.Manifest{
		Versioned: manifest.Versioned{
			SchemaVersion: 1,
		},
		Name: repoName,
		Tag:  tag,
	}

	// Parse repository name reference
	repoRef, err := reference.WithName(repoName)
	if err != nil {
		t.Fatalf("unable to parse reference for repository name %s: %v", repoName, err)
	}

	// Get the repository from the namespace
	repository, err := registry.Repository(ctx, repoRef)
	if err != nil {
		t.Fatalf("unexpected error getting repository '%s': %v", repoName, err)
	}

	// Create blobs and add them to the manifest
	for i := 0; i < blobsCount; i++ {
		wr, err := repository.Blobs(ctx).Create(ctx)
		if err != nil {
			t.Fatalf("unexpected error creating test upload for blob %d: %v", i, err)
		}

		// Generate a random tar file
		rs, blobDgst, err := testutil.CreateRandomTarFile()
		if err != nil {
			t.Fatalf("unexpected error generating test layer file for blob %d: %v", i, err)
		}

		// Copy data into the blob
		if _, err := io.Copy(wr, rs); err != nil {
			t.Fatalf("unexpected error copying to upload for blob %d: %v", i, err)
		}

		// Commit the blob
		if _, err := wr.Commit(ctx, distribution.Descriptor{Digest: blobDgst}); err != nil {
			t.Fatalf("unexpected error committing upload for blob %d: %v", i, err)
		}

		// Create a reference for the blob
		blobRef, err := reference.WithDigest(repoRef, blobDgst)
		if err != nil {
			t.Fatalf("failed to create blob reference for blob %d: %v", i, err)
		}

		blobsRefs = append(blobsRefs, blobRef)

		// Add blob information to the manifest
		m.FSLayers = append(m.FSLayers, schema1.FSLayer{BlobSum: blobDgst})
		m.History = append(m.History, schema1.History{V1Compatibility: fmt.Sprintf(`{"id": "%d"}`, i)})
	}

	// Generate a private key for signing the manifest
	pk, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		t.Fatalf("unexpected error generating private key: %v", err)
	}

	// Sign the manifest
	sm, err := schema1.Sign(&m, pk)
	if err != nil {
		t.Fatalf("error signing manifest: %v", err)
	}

	// Get the manifest service from the repository
	ms, err := repository.Manifests(ctx)
	if err != nil {
		t.Fatalf("error retrieving manifests from repository: %v", err)
	}

	// Store the manifest in the repository
	manifestDgst, err := ms.Put(ctx, sm)
	if err != nil {
		t.Fatalf("unexpected error putting manifest: %v", err)
	}

	// Create a reference for the manifest
	manifestRef, err := reference.WithDigest(repoRef, manifestDgst)
	if err != nil {
		t.Fatalf("failed to create manifest reference: %v", err)
	}

	return manifestRef, blobsRefs
}

func testRefs(t *testing.T) (reference.Reference, reference.Reference, reference.Reference) {
	ref1, err := reference.Parse("testrepo@sha256:aaaaeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("could not parse reference: %v", err)
	}

	ref2, err := reference.Parse("testrepo@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("could not parse reference: %v", err)
	}

	ref3, err := reference.Parse("testrepo@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatalf("could not parse reference: %v", err)
	}

	return ref1, ref2, ref3
}

func TestSchedule(t *testing.T) {
	driver, registry := newRegistry(t)
	ttl := 24 * 7 * time.Hour

	ref1, ref2, ref3 := testRefs(t)
	timeUnit := time.Millisecond
	remainingRepos := map[string]bool{
		ref1.String(): true,
		ref2.String(): true,
		ref3.String(): true,
	}

	var mu sync.Mutex
	s := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, "/ttl")
	deleteFunc := func(repoName reference.Reference) error {
		if len(remainingRepos) == 0 {
			t.Fatalf("Incorrect expiry count")
		}
		_, ok := remainingRepos[repoName.String()]
		if !ok {
			t.Fatalf("Trying to remove nonexistent repo: %s", repoName)
		}
		t.Log("removing", repoName)
		mu.Lock()
		delete(remainingRepos, repoName.String())
		mu.Unlock()

		return nil
	}
	s.onBlobExpire = deleteFunc
	err := s.Start()
	if err != nil {
		t.Fatalf("Error starting ttlExpirationScheduler: %s", err)
	}

	s.add(ref1, 3*timeUnit, entryTypeBlob)
	s.add(ref2, 1*timeUnit, entryTypeBlob)

	func() {
		s.Lock()
		s.add(ref3, 1*timeUnit, entryTypeBlob)
		s.Unlock()

	}()

	// Ensure all repos are deleted
	<-time.After(50 * timeUnit)

	mu.Lock()
	defer mu.Unlock()
	if len(remainingRepos) != 0 {
		t.Fatalf("Repositories remaining: %#v", remainingRepos)
	}
}

func TestRestoreOld(t *testing.T) {
	driver, registry := newRegistry(t)
	ttl := 24 * 7 * time.Hour

	ref1, ref2, _ := testRefs(t)
	remainingRepos := map[string]bool{
		ref1.String(): true,
		ref2.String(): true,
	}

	var wg sync.WaitGroup
	wg.Add(len(remainingRepos))
	var mu sync.Mutex
	deleteFunc := func(r reference.Reference) error {
		mu.Lock()
		defer mu.Unlock()
		if r.String() == ref1.String() && len(remainingRepos) == 2 {
			t.Errorf("ref1 should not be removed first")
		}
		_, ok := remainingRepos[r.String()]
		if !ok {
			t.Fatalf("Trying to remove nonexistent repo: %s", r)
		}
		delete(remainingRepos, r.String())
		wg.Done()
		return nil
	}

	timeUnit := time.Millisecond
	serialized, err := json.Marshal(&map[string]schedulerEntry{
		ref1.String(): {
			Expiry:    time.Now().Add(10 * timeUnit),
			Key:       ref1.String(),
			EntryType: 0,
		},
		ref2.String(): {
			Expiry:    time.Now().Add(-3 * timeUnit), // TTL passed, should be removed first
			Key:       ref2.String(),
			EntryType: 0,
		},
	})
	if err != nil {
		t.Fatalf("Error serializing test data: %s", err.Error())
	}

	ctx := context.Background()
	pathToStatFile := "/ttl"
	err = driver.PutContent(ctx, pathToStatFile, serialized)
	if err != nil {
		t.Fatal("Unable to write serialized data to fs")
	}
	s := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, "/ttl")
	s.OnBlobExpire(deleteFunc)
	err = s.Start()
	if err != nil {
		t.Fatalf("Error starting ttlExpirationScheduler: %s", err)
	}
	defer s.Stop()

	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(remainingRepos) != 0 {
		t.Fatalf("Repositories remaining: %#v", remainingRepos)
	}

	// Check state file, it should be empty
	<-time.After(5 * time.Second)
	content, err := driver.GetContent(ctx, pathToStatFile)
	if err != nil {
		t.Fatal("Unable to get data from fs")
	}

	var serializedContent map[string]*schedulerEntry
	if err = json.Unmarshal(content, &serializedContent); err != nil {
		t.Fatalf("Error unmarshaling content: %s", err)
	}
	if len(serializedContent) != 0 {
		t.Fatalf("Repositories remaining: %#v", serializedContent)
	}
}

func TestStoreState(t *testing.T) {
	pathToStatFile := "/ttl"
	timeUnit := time.Second

	ctx := context.Background()
	driver, registry := newRegistry(t)
	v := storage.NewVacuum(ctx, driver)
	ttl := 24 * 7 * time.Hour

	// Create img1, img2, img3
	manifestRef1, blobsRef1 := populateRepo(ctx, t, registry, "test", "latest", 1)
	manifestRef2, blobsRef2 := populateRepo(ctx, t, registry, "a/b/c", "latest", 3)
	manifestRef3, blobsRef3 := populateRepo(ctx, t, registry, "c/d/e", "latest", 6)

	onBlobExpire := func(ref reference.Reference) error {
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

		err = blobs.Delete(ctx, r.Digest())
		if err != nil {
			return err
		}

		err = v.RemoveBlob(r.Digest().String())
		if err != nil {
			return err
		}

		return nil
	}

	onManifestExpire := func(ref reference.Reference) error {
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
	}

	// Create default state with img1 and img2 (Expiry after 1 seconds)
	schedulerEntries := map[string]*schedulerEntry{}
	for _, manifest := range []reference.Canonical{manifestRef1, manifestRef2} {
		schedulerEntries[manifest.String()] = &schedulerEntry{
			Expiry:    time.Now().Add(1 * timeUnit),
			Key:       manifest.String(),
			EntryType: entryTypeManifest,
		}
	}
	for _, blob := range append(blobsRef1, blobsRef2...) {
		schedulerEntries[blob.String()] = &schedulerEntry{
			Expiry:    time.Now().Add(1 * timeUnit),
			Key:       blob.String(),
			EntryType: entryTypeBlob,
		}
	}
	serialized, err := json.Marshal(&schedulerEntries)
	if err != nil {
		t.Fatalf("Error serializing test data: %s", err.Error())
	}
	err = driver.PutContent(ctx, pathToStatFile, serialized)
	if err != nil {
		t.Fatal("Unable to write serialized data to fs")
	}

	// Start sheduler
	s := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStatFile)
	s.OnBlobExpire(onBlobExpire)
	s.OnManifestExpire(onManifestExpire)
	err = s.Start()
	if err != nil {
		t.Fatalf("Unable to start scheduler: %v", err)
	}

	// Add img3 (Expiry after repositoryTTL time)
	s.AddManifest(manifestRef3)
	for _, blob := range blobsRef3 {
		s.AddBlob(blob)
	}

	// Wait Expiry img1 and img2, and save state file in storage
	<-time.After(5 * timeUnit)
	s.Stop()

	// Read the state file content after the first scheduler stop
	content, err := driver.GetContent(ctx, pathToStatFile)
	if err != nil {
		t.Fatalf("Error reading state file after first scheduler stop: %v", err)
	}

	// Expected only img3 in state file
	var serializedContent map[string]*schedulerEntryTest
	if err = json.Unmarshal(content, &serializedContent); err != nil {
		t.Fatalf("Error unmarshaling content: %s", err)
	}
	if len(serializedContent) == 0 {
		t.Fatalf("Repositories remaining: %#v", serializedContent)
	}

	expecterContent := map[string]*schedulerEntryTest{}
	for _, manifest := range []reference.Canonical{manifestRef3} {
		expecterContent[manifest.String()] = &schedulerEntryTest{EntryType: entryTypeManifest}
	}
	for _, blob := range blobsRef3 {
		expecterContent[blob.String()] = &schedulerEntryTest{EntryType: entryTypeBlob}
	}
	compareSchedulerEntryTests(t, serializedContent, expecterContent)
}

func TestStopRestore(t *testing.T) {
	driver, registry := newRegistry(t)
	ttl := 24 * 7 * time.Hour

	ref1, ref2, _ := testRefs(t)

	timeUnit := time.Millisecond
	remainingRepos := map[string]bool{
		ref1.String(): true,
		ref2.String(): true,
	}

	var mu sync.Mutex
	deleteFunc := func(r reference.Reference) error {
		mu.Lock()
		delete(remainingRepos, r.String())
		mu.Unlock()
		return nil
	}

	pathToStateFile := "/ttl"
	s := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStateFile)
	s.onBlobExpire = deleteFunc

	err := s.Start()
	if err != nil {
		t.Fatalf(err.Error())
	}
	s.add(ref1, 300*timeUnit, entryTypeBlob)
	s.add(ref2, 100*timeUnit, entryTypeBlob)

	// Start and stop before all operations complete
	// state will be written to fs
	s.Stop()
	time.Sleep(10 * time.Millisecond)

	// v2 will restore state from fs
	s2 := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStateFile)
	s2.onBlobExpire = deleteFunc
	err = s2.Start()
	if err != nil {
		t.Fatalf("Error starting v2: %s", err.Error())
	}

	<-time.After(500 * timeUnit)
	mu.Lock()
	defer mu.Unlock()
	if len(remainingRepos) != 0 {
		t.Fatalf("Repositories remaining: %#v", remainingRepos)
	}

}

func TestFillStateFromStorageExpireState(t *testing.T) {
	var mu sync.Mutex
	timeUnit := time.Millisecond
	pathToStatFile := "/ttl"
	ttl := 10 * timeUnit

	allManifests := map[reference.Canonical]struct{}{}
	allBlobs := map[reference.Canonical]struct{}{}

	ctx := context.Background()
	driver, registry := newRegistry(t)

	// Create img1, img2, img3
	manifest1, blobs1 := populateRepo(ctx, t, registry, "test", "latest", 1)
	manifest2, blobs2 := populateRepo(ctx, t, registry, "a/b/c", "latest", 3)
	manifest3, blobs3 := populateRepo(ctx, t, registry, "c/d/e", "latest", 6)

	allManifests[manifest1] = struct{}{}
	allManifests[manifest2] = struct{}{}
	allManifests[manifest3] = struct{}{}
	for _, blob := range blobs1 {
		allBlobs[blob] = struct{}{}
	}
	for _, blob := range blobs2 {
		allBlobs[blob] = struct{}{}
	}
	for _, blob := range blobs3 {
		allBlobs[blob] = struct{}{}
	}

	onBlobExpire := func(ref reference.Reference) error {
		t.Log("removing blob", ref.String())
		if len(allBlobs) == 0 {
			t.Fatalf("Incorrect expiry count")
		}
		var r reference.Canonical
		var ok bool
		if r, ok = ref.(reference.Canonical); !ok {
			t.Fatalf("unexpected reference type: %T", ref)
		}
		_, ok = allBlobs[r]
		if !ok {
			t.Fatalf("Trying to remove nonexistent blob: %s", r.String())
		}
		mu.Lock()
		delete(allBlobs, r)
		mu.Unlock()
		return nil
	}
	onManifestExpire := func(ref reference.Reference) error {
		t.Log("removing manifest", ref.String())
		if len(allManifests) == 0 {
			t.Fatalf("Incorrect expiry count")
		}
		var r reference.Canonical
		var ok bool
		if r, ok = ref.(reference.Canonical); !ok {
			t.Fatalf("unexpected reference type: %T", ref)
		}
		_, ok = allManifests[r]
		if !ok {
			t.Fatalf("Trying to remove nonexistent manifests: %s", r.String())
		}
		mu.Lock()
		delete(allManifests, r)
		mu.Unlock()
		return nil
	}

	// Start sheduler with empty state, expected startFiller
	s := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStatFile)
	s.OnBlobExpire(onBlobExpire)
	s.OnManifestExpire(onManifestExpire)
	err := s.Start()
	if err != nil {
		t.Fatalf("Unable to start scheduler: %v", err)
	}
	defer s.Stop()

	<-time.After(500 * timeUnit)

	mu.Lock()
	defer mu.Unlock()

	// Expected empty blobs and manifests lists
	if len(allBlobs) != 0 {
		t.Fatalf("Blobs remaining: %#v", len(allBlobs))
	}
	if len(allManifests) != 0 {
		t.Fatalf("Manifests remaining: %#v", len(allManifests))
	}
}

func TestFillStateFromStorageStoreState(t *testing.T) {
	pathToStatFile := "/ttl"
	ttl := 10000 * time.Hour

	ctx := context.Background()
	driver, registry := newRegistry(t)
	v := storage.NewVacuum(ctx, driver)

	// Create img1, img2, img3
	manifestRef1, blobsRef1 := populateRepo(ctx, t, registry, "test", "latest", 1)
	manifestRef2, blobsRef2 := populateRepo(ctx, t, registry, "a/b/c", "latest", 3)
	manifestRef3, blobsRef3 := populateRepo(ctx, t, registry, "c/d/e", "latest", 6)

	// Create the first scheduler
	onBlobExpire := func(ref reference.Reference) error {
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

		err = v.RemoveBlob(r.Digest().String())
		if err != nil {
			return err
		}

		return nil
	}

	onManifestExpire := func(ref reference.Reference) error {
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
	}

	// Start sheduler with empty state, expected startFiller
	s := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStatFile)
	s.OnBlobExpire(onBlobExpire)
	s.OnManifestExpire(onManifestExpire)
	err := s.Start()
	if err != nil {
		t.Fatalf("Unable to start scheduler: %v", err)
	}

	// Let the scheduler run for a while
	<-time.After(1 * time.Second)
	s.Stop()

	// Read the state file content after the first scheduler stop
	// Expected state with img1, img2, img3 manifests and blobs
	content, err := driver.GetContent(ctx, pathToStatFile)
	if err != nil {
		t.Fatalf("Error reading state file after first scheduler stop: %v", err)
	}

	var serializedContent map[string]*schedulerEntryTest
	if err = json.Unmarshal(content, &serializedContent); err != nil {
		t.Fatalf("Error unmarshaling content: %s", err)
	}
	if len(serializedContent) == 0 {
		t.Fatalf("Repositories remaining: %#v", serializedContent)
	}

	expecterContent := map[string]*schedulerEntryTest{}
	for _, manifest := range []reference.Canonical{manifestRef1, manifestRef2, manifestRef3} {
		expecterContent[manifest.String()] = &schedulerEntryTest{EntryType: entryTypeManifest}
	}
	for _, blob := range append(blobsRef1, append(blobsRef2, blobsRef3...)...) {
		expecterContent[blob.String()] = &schedulerEntryTest{EntryType: entryTypeBlob}
	}
	compareSchedulerEntryTests(t, serializedContent, expecterContent)
}

func TestFillStateFromStorageStoreAndUpdateState(t *testing.T) {
	timeUnit := time.Millisecond
	pathToStatFile := "/ttl"
	ttl := 10000 * timeUnit

	ctx := context.Background()
	driver, registry := newRegistry(t)
	v := storage.NewVacuum(ctx, driver)

	// Create img1, img2, img3
	_, _ = populateRepo(ctx, t, registry, "test", "latest", 1)
	_, _ = populateRepo(ctx, t, registry, "a/b/c", "latest", 3)
	_, _ = populateRepo(ctx, t, registry, "c/d/e", "latest", 6)

	// Create the first scheduler
	onBlobExpire := func(ref reference.Reference) error {
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

		err = v.RemoveBlob(r.Digest().String())
		if err != nil {
			return err
		}

		return nil
	}

	onManifestExpire := func(ref reference.Reference) error {
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
	}

	// Start and stop sheduler with empty state, expected startFiller
	s1 := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStatFile)
	s1.OnBlobExpire(onBlobExpire)
	s1.OnManifestExpire(onManifestExpire)
	err := s1.Start()
	if err != nil {
		t.Fatalf("Unable to start scheduler: %v", err)
	}
	<-time.After(100 * timeUnit)
	s1.Stop()

	// Read the state file content after the first scheduler stop
	bytes1, err := driver.GetContent(ctx, pathToStatFile)
	if err != nil {
		t.Fatalf("Error reading state file after first scheduler stop: %v", err)
	}

	// Load a new image (img 4)
	manifestRef, blobsRef := populateRepo(ctx, t, registry, "f/g/h", "latest", 2)

	// Start and stop sheduler with not empty state, not expected startFiller
	s2 := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStatFile)
	s2.OnBlobExpire(onBlobExpire)
	s2.OnManifestExpire(onManifestExpire)
	err = s2.Start()
	if err != nil {
		t.Fatalf("Unable to start second scheduler: %v", err)
	}
	<-time.After(100 * timeUnit)
	s2.Stop()

	// Read the state file content after the second scheduler stop
	bytes2, err := driver.GetContent(ctx, pathToStatFile)
	if err != nil {
		t.Fatalf("Error reading state file after second scheduler stop: %v", err)
	}

	// Exprected unchange
	if string(bytes1) != string(bytes2) {
		t.Errorf("Expected bytes1 and bytes2 to be equal, but they differ.\nbytes1: %s\nbytes2: %s", string(bytes1), string(bytes2))
	}

	// Create the third scheduler
	s3 := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, pathToStatFile)
	s3.OnBlobExpire(onBlobExpire)
	s3.OnManifestExpire(onManifestExpire)
	err = s3.Start()
	if err != nil {
		t.Fatalf("Unable to start third scheduler: %v", err)
	}

	// Add data to the scheduler with new img4
	s3.AddManifest(manifestRef)
	for _, blob := range blobsRef {
		s3.AddBlob(blob)
	}

	<-time.After(100 * timeUnit)
	s3.Stop()

	// Read the state file content after data was added to the scheduler
	bytes3, err := driver.GetContent(ctx, pathToStatFile)
	if err != nil {
		t.Fatalf("Error reading state file after third scheduler stop: %v", err)
	}

	// Exprected changes with img4
	if string(bytes2) == string(bytes3) {
		t.Errorf("Expected bytes2 and bytes3 to be different, but they are equal.\nbytes2: %s\nbytes3: %s", string(bytes2), string(bytes3))
	}
}

func TestDoubleStart(t *testing.T) {
	driver, registry := newRegistry(t)
	ttl := 24 * 7 * time.Hour

	s := newTTLExpirationScheduler(context.Background(), ttl, driver, registry, "/ttl")
	err := s.Start()
	if err != nil {
		t.Fatalf("Unable to start scheduler")
	}
	err = s.Start()
	if err == nil {
		t.Fatalf("Scheduler started twice without error")
	}
}

func compareSchedulerEntryTests(t *testing.T, map1, map2 map[string]*schedulerEntryTest) {
	// Check if lengths of the maps are different
	if len(map1) != len(map2) {
		t.Fatalf("Maps are of different lengths: len(map1) = %d, len(map2) = %d", len(map1), len(map2))
	}

	// Iterate through the first map
	for key, entry1 := range map1 {
		entry2, ok := map2[key]

		// Check if key exists in map2
		if !ok {
			t.Fatalf("Key %s found in map1 but not in map2", key)
		}

		// Handle cases where one or both of the entries are nil
		if entry1 == nil || entry2 == nil {
			if entry1 != entry2 { // One is nil, the other is not
				t.Fatalf("Value for key %s is nil in one map but not the other: map1[%s] = %v, map2[%s] = %v", key, key, entry1, key, entry2)
			}
		} else {
			// Compare the fields of sEntry structs
			if entry1.EntryType != entry2.EntryType {
				t.Fatalf("Values for key %s differ: map1[%s].EntryType = %d, map2[%s].EntryType = %d", key, key, entry1.EntryType, key, entry2.EntryType)
			}
		}
	}
}
