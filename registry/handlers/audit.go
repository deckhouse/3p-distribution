package handlers

import (
	"github.com/opencontainers/go-digest"
)

// auditFields builds the structured fields for a registry audit log entry
// describing a write operation (push/delete) on a repository. It is logged
// together with the authenticated identity (auth.user.name) so that successful
// push and delete operations are attributable in the registry logs. Empty tag
// or digest are omitted (e.g. a delete is addressed by digest, not tag).
func auditFields(action, repository, tag string, dgst digest.Digest) map[interface{}]interface{} {
	fields := map[interface{}]interface{}{
		"audit.action":     action,
		"audit.repository": repository,
	}
	if tag != "" {
		fields["audit.tag"] = tag
	}
	if dgst != "" {
		fields["audit.digest"] = dgst.String()
	}
	return fields
}
