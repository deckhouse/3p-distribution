package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/distribution"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/storage/driver"
	"github.com/opencontainers/go-digest"
)

// onTTLExpiryFunc is called when a repository's TTL expires
type expiryFunc func(reference.Reference) error

const (
	entryTypeBlob = iota
	entryTypeManifest
	indexSaveFrequency = 5 * time.Second
)

// schedulerEntry represents an entry in the scheduler
// fields are exported for serialization
type schedulerEntry struct {
	Key       string    `json:"Key"`
	Expiry    time.Time `json:"ExpiryData"`
	EntryType int       `json:"EntryType"`

	timer *time.Timer
}

// New returns a new instance of the scheduler
func New(ctx context.Context, ttl time.Duration, driver driver.StorageDriver, registry distribution.Namespace, path string) *TTLExpirationScheduler {
	return &TTLExpirationScheduler{
		entries:         make(map[string]*schedulerEntry),
		ttl:             ttl,
		registry:        registry,
		driver:          driver,
		pathToStateFile: path,
		ctx:             ctx,
		stopped:         true,
		doneChan:        make(chan struct{}),
		saveTimer:       time.NewTicker(indexSaveFrequency),
	}
}

// TTLExpirationScheduler is a scheduler used to perform actions
// when TTLs expire
type TTLExpirationScheduler struct {
	sync.Mutex

	entries map[string]*schedulerEntry

	registry        distribution.Namespace
	driver          driver.StorageDriver
	ctx             context.Context
	ttl             time.Duration
	pathToStateFile string

	stopped bool

	onBlobExpire     expiryFunc
	onManifestExpire expiryFunc

	indexDirty bool
	saveTimer  *time.Ticker
	doneChan   chan struct{}

	startFiller bool // Default - false
}

// OnBlobExpire is called when a scheduled blob's TTL expires
func (ttles *TTLExpirationScheduler) OnBlobExpire(f expiryFunc) {
	ttles.Lock()
	defer ttles.Unlock()

	ttles.onBlobExpire = f
}

// OnManifestExpire is called when a scheduled manifest's TTL expires
func (ttles *TTLExpirationScheduler) OnManifestExpire(f expiryFunc) {
	ttles.Lock()
	defer ttles.Unlock()

	ttles.onManifestExpire = f
}

// AddBlob schedules a blob cleanup after ttl expires
func (ttles *TTLExpirationScheduler) AddBlob(blobRef reference.Canonical) error {
	ttles.Lock()
	defer ttles.Unlock()

	if ttles.stopped {
		return fmt.Errorf("scheduler not started")
	}

	ttles.add(blobRef, entryTypeBlob)
	return nil
}

// AddManifest schedules a manifest cleanup after ttl expires
func (ttles *TTLExpirationScheduler) AddManifest(manifestRef reference.Canonical) error {
	ttles.Lock()
	defer ttles.Unlock()

	if ttles.stopped {
		return fmt.Errorf("scheduler not started")
	}

	ttles.add(manifestRef, entryTypeManifest)
	return nil
}

// Start starts the scheduler
func (ttles *TTLExpirationScheduler) Start() error {
	ttles.Lock()
	defer ttles.Unlock()

	err := ttles.readState()
	if err != nil {
		return err
	}

	if !ttles.stopped {
		return fmt.Errorf("scheduler already started")
	}

	dcontext.GetLogger(ttles.ctx).Infof("Starting cached object TTL expiration scheduler...")
	ttles.stopped = false

	// Start timer for each deserialized entry
	for _, entry := range ttles.entries {
		entry.timer = ttles.startTimer(entry, time.Until(entry.Expiry))
	}

	// Start a ticker to periodically save the entries index

	go func() {
		for {
			select {
			case <-ttles.saveTimer.C:
				ttles.Lock()
				if !ttles.indexDirty {
					ttles.Unlock()
					continue
				}

				err := ttles.writeState()
				if err != nil {
					dcontext.GetLogger(ttles.ctx).Errorf("Error writing scheduler state: %s", err)
				} else {
					ttles.indexDirty = false
				}
				ttles.Unlock()

			case <-ttles.doneChan:
				return
			}
		}
	}()

	if ttles.startFiller {
		go func() {
			for {
				dcontext.GetLogger(ttles.ctx).Infof("Starting cache loading from storage...")
				err := ttles.fillStateFromStorage()
				if err != nil {
					dcontext.GetLogger(ttles.ctx).Errorf("Error loading scheduler state: %s", err)
					time.Sleep(20 * time.Second)
				} else {
					break
				}
			}

			ttles.Lock()
			defer ttles.Unlock()
			ttles.startFiller = false

			err = ttles.writeState()
			if err != nil {
				dcontext.GetLogger(ttles.ctx).Errorf("Error writing scheduler state: %s", err)
			}
			dcontext.GetLogger(ttles.ctx).Infof("Cache loading from storage completed successfully.")
		}()
	}
	return nil
}

func (ttles *TTLExpirationScheduler) add(r reference.Reference, eType int) {
	entry := &schedulerEntry{
		Key:       r.String(),
		Expiry:    time.Now().Add(ttles.ttl),
		EntryType: eType,
	}
	dcontext.GetLogger(ttles.ctx).Infof("Adding new scheduler entry for %s with ttl=%s", entry.Key, time.Until(entry.Expiry))
	if oldEntry, present := ttles.entries[entry.Key]; present && oldEntry.timer != nil {
		oldEntry.timer.Stop()
	}
	ttles.entries[entry.Key] = entry
	entry.timer = ttles.startTimer(entry, ttles.ttl)
	ttles.indexDirty = true
}

func (ttles *TTLExpirationScheduler) startTimer(entry *schedulerEntry, ttl time.Duration) *time.Timer {
	return time.AfterFunc(ttl, func() {
		ttles.Lock()
		defer ttles.Unlock()

		var f expiryFunc

		switch entry.EntryType {
		case entryTypeBlob:
			f = ttles.onBlobExpire
		case entryTypeManifest:
			f = ttles.onManifestExpire
		default:
			f = func(reference.Reference) error {
				return fmt.Errorf("scheduler entry type")
			}
		}

		ref, err := reference.Parse(entry.Key)
		if err == nil {
			if err := f(ref); err != nil {
				dcontext.GetLogger(ttles.ctx).Errorf("Scheduler error returned from OnExpire(%s): %s", entry.Key, err)
			}
		} else {
			dcontext.GetLogger(ttles.ctx).Errorf("Error unpacking reference: %s", err)
		}

		delete(ttles.entries, entry.Key)
		ttles.indexDirty = true
	})
}

// Stop stops the scheduler.
func (ttles *TTLExpirationScheduler) Stop() {
	ttles.Lock()
	defer ttles.Unlock()

	if err := ttles.writeState(); err != nil {
		dcontext.GetLogger(ttles.ctx).Errorf("Error writing scheduler state: %s", err)
	}

	for _, entry := range ttles.entries {
		entry.timer.Stop()
	}

	close(ttles.doneChan)
	ttles.saveTimer.Stop()
	ttles.stopped = true
}

func (ttles *TTLExpirationScheduler) writeState() error {
	if ttles.startFiller {
		dcontext.GetLogger(ttles.ctx).Warnf("Writing state is not allowed")
		return nil
	}
	jsonBytes, err := json.Marshal(ttles.entries)
	if err != nil {
		return err
	}

	err = ttles.driver.PutContent(ttles.ctx, ttles.pathToStateFile, jsonBytes)
	if err != nil {
		return err
	}
	return nil
}

func (ttles *TTLExpirationScheduler) readState() error {
	if _, err := ttles.driver.Stat(ttles.ctx, ttles.pathToStateFile); err != nil {
		switch err := err.(type) {
		case driver.PathNotFoundError:
			ttles.startFiller = true
			return nil
		default:
			return err
		}
	}

	bytes, err := ttles.driver.GetContent(ttles.ctx, ttles.pathToStateFile)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, &ttles.entries)
	if err != nil {
		return err
	}
	return nil
}

// loadStateFromStorage sets expiration (TTL) for manifests and blobs in the repository
func (ttles *TTLExpirationScheduler) fillStateFromStorage() error {
	// Convert registry to a RepositoryEnumerator to enable repository iteration
	repositoryEnumerator, ok := ttles.registry.(distribution.RepositoryEnumerator)
	if !ok {
		return fmt.Errorf("unable to convert Namespace to RepositoryEnumerator")
	}

	// Maps to track manifests and blobs that will have TTLs assigned
	manifestRefSet := make(map[reference.Canonical]struct{})
	blobRefMap := make(map[digest.Digest]reference.Canonical)

	// Iterate through all repositories in the registry
	err := repositoryEnumerator.Enumerate(ttles.ctx, func(repoName string) error {
		named, err := reference.WithName(repoName)
		if err != nil {
			return fmt.Errorf("failed to parse repo name %s: %v", repoName, err)
		}

		// Get the repository object for the current repoName
		repository, err := ttles.registry.Repository(ttles.ctx, named)
		if err != nil {
			return fmt.Errorf("failed to construct repository: %v", err)
		}

		// Get the manifest service for this repository
		manifestService, err := repository.Manifests(ttles.ctx)
		if err != nil {
			return fmt.Errorf("failed to construct manifest service: %v", err)
		}

		// Convert the manifest service to a ManifestEnumerator for manifest iteration
		manifestEnumerator, ok := manifestService.(distribution.ManifestEnumerator)
		if !ok {
			return fmt.Errorf("unable to convert ManifestService into ManifestEnumerator")
		}

		// Enumerate through all manifests in the repository
		err = manifestEnumerator.Enumerate(ttles.ctx, func(dgst digest.Digest) error {
			// Add the manifest reference to the tracking set
			manifestRef, err := reference.WithDigest(named, dgst)
			if err != nil {
				return fmt.Errorf("failed to create manifest reference: %v", err)
			}
			manifestRefSet[manifestRef] = struct{}{}

			// Get the manifest data for the given digest
			manifest, err := manifestService.Get(ttles.ctx, dgst)
			if err != nil {
				return fmt.Errorf("failed to retrieve manifest for digest %v: %v", dgst, err)
			}

			// Add all blobs referenced by the manifest to the blob tracking map
			descriptors := manifest.References()
			for _, descriptor := range descriptors {
				blobDigest := descriptor.Digest
				blobRef, err := reference.WithDigest(named, descriptor.Digest)
				if err != nil {
					return fmt.Errorf("failed to create blob reference: %v", err)
				}
				blobRefMap[blobDigest] = blobRef
			}
			return nil
		})

		// Handle non-existent paths such as unfinished uploads or deleted content
		if err != nil {
			if _, ok := err.(driver.PathNotFoundError); !ok {
				return fmt.Errorf("failed to mark manifests: %v", err)
			}
		}
		return nil
	})

	if err != nil {
		if _, ok := err.(driver.PathNotFoundError); !ok {
			return fmt.Errorf("failed to mark repositories: %v", err)
		}
	}

	// Map to track blob references
	blobRefSet := make(map[reference.Canonical]struct{})
	blobEnumerator := ttles.registry.Blobs()

	// Enumerate through all blobs in the registry
	err = blobEnumerator.Enumerate(ttles.ctx, func(dgst digest.Digest) error {
		blobRef, ok := blobRefMap[dgst]
		if ok {
			blobRefSet[blobRef] = struct{}{}
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(driver.PathNotFoundError); !ok {
			return fmt.Errorf("failed to mark blobs: %v", err)
		}
	}

	ttles.Lock()
	defer ttles.Unlock()
	// Schedule TTL for all tracked manifests
	for manifestRef := range manifestRefSet {
		ttles.add(manifestRef, entryTypeManifest)
	}

	// Schedule TTL for all tracked blobs
	for blobRef := range blobRefSet {
		ttles.add(blobRef, entryTypeBlob)
	}
	return nil
}
