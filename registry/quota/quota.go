// Package quota implements per-project (namespace) storage quota accounting and
// enforcement for the registry. A project's usage is the physical footprint of
// the distinct blobs stored for the project (referenced or orphaned, until GC
// reclaims them), so deleting manifests does not free quota until GC runs.
package quota

// WouldExceed reports whether adding incoming bytes to the current footprint
// would exceed the limit. A limit <= 0 means "unlimited" (no quota).
func WouldExceed(currentFootprint, incoming, limit int64) bool {
	if limit <= 0 {
		return false
	}
	return currentFootprint+incoming > limit
}

// BlobSize pairs a blob digest with its size in bytes.
type BlobSize struct {
	Digest string
	Size   int64
}

// Footprint sums the sizes of the distinct blobs (deduplicated by digest).
func Footprint(blobs []BlobSize) int64 {
	seen := make(map[string]struct{}, len(blobs))
	var total int64
	for _, b := range blobs {
		if _, ok := seen[b.Digest]; ok {
			continue
		}
		seen[b.Digest] = struct{}{}
		total += b.Size
	}
	return total
}
