package handlers

import (
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestAuditFields(t *testing.T) {
	const dgst = digest.Digest("sha256:1111111111111111111111111111111111111111111111111111111111111111")

	t.Run("push carries action, repository, tag and digest", func(t *testing.T) {
		f := auditFields("push", "test/ci/app", "v2", dgst)
		if f["audit.action"] != "push" {
			t.Errorf("audit.action = %v, want push", f["audit.action"])
		}
		if f["audit.repository"] != "test/ci/app" {
			t.Errorf("audit.repository = %v, want test/ci/app", f["audit.repository"])
		}
		if f["audit.tag"] != "v2" {
			t.Errorf("audit.tag = %v, want v2", f["audit.tag"])
		}
		if f["audit.digest"] != dgst.String() {
			t.Errorf("audit.digest = %v, want %v", f["audit.digest"], dgst.String())
		}
	})

	t.Run("delete by digest omits empty tag", func(t *testing.T) {
		f := auditFields("delete", "test/ci/app", "", dgst)
		if f["audit.action"] != "delete" {
			t.Errorf("audit.action = %v, want delete", f["audit.action"])
		}
		if _, ok := f["audit.tag"]; ok {
			t.Errorf("audit.tag should be omitted when empty, got %v", f["audit.tag"])
		}
		if f["audit.digest"] != dgst.String() {
			t.Errorf("audit.digest = %v, want %v", f["audit.digest"], dgst.String())
		}
	})

	t.Run("empty digest is omitted", func(t *testing.T) {
		f := auditFields("push", "test/ci/app", "v2", "")
		if _, ok := f["audit.digest"]; ok {
			t.Errorf("audit.digest should be omitted when empty, got %v", f["audit.digest"])
		}
	})
}
