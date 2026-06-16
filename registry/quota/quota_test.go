package quota

import "testing"

func TestWouldExceed(t *testing.T) {
	cases := []struct {
		name                       string
		footprint, incoming, limit int64
		want                       bool
	}{
		{"under", 100, 10, 1000, false},
		{"exactly at limit is allowed", 990, 10, 1000, false},
		{"one over", 991, 10, 1000, true},
		{"zero limit means unlimited", 1 << 40, 1 << 30, 0, false},
		{"negative limit means unlimited", 100, 100, -1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WouldExceed(c.footprint, c.incoming, c.limit); got != c.want {
				t.Fatalf("WouldExceed(%d,%d,%d)=%v, want %v", c.footprint, c.incoming, c.limit, got, c.want)
			}
		})
	}
}

func TestFootprintSumsDistinctBlobs(t *testing.T) {
	blobs := []BlobSize{
		{Digest: "sha256:a", Size: 100},
		{Digest: "sha256:b", Size: 200},
		{Digest: "sha256:a", Size: 100}, // duplicate across repos — counted once
	}
	if got := Footprint(blobs); got != 300 {
		t.Fatalf("Footprint=%d, want 300", got)
	}
}

func TestFootprintEmpty(t *testing.T) {
	if got := Footprint(nil); got != 0 {
		t.Fatalf("Footprint(nil)=%d, want 0", got)
	}
}
