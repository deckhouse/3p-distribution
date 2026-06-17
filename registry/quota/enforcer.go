package quota

import (
	"context"
	"errors"
	"fmt"
)

// ErrQuotaExceeded is returned by Enforcer.Check when admitting the blob would
// exceed the project's quota. Callers map it to HTTP 413. Any other error is a
// fail-closed condition (the quota could not be evaluated) and should map to a
// retriable HTTP 503.
var ErrQuotaExceeded = errors.New("project quota exceeded")

// LimitProvider resolves a namespace's quota limit in bytes (0 = unlimited).
type LimitProvider interface {
	Limit(ctx context.Context, namespace string) (int64, error)
}

// FootprintProvider resolves a namespace's current physical footprint in bytes.
type FootprintProvider interface {
	Footprint(ctx context.Context, namespace string) (int64, error)
}

// UsageReporter reports a namespace's current usage so it can be surfaced (e.g.
// in the PayloadRegistryQuota status).
type UsageReporter interface {
	ReportUsage(ctx context.Context, namespace string, used int64) error
}

// Enforcer decides whether a blob of a given size may be admitted to a project.
type Enforcer struct {
	limits     LimitProvider
	footprints FootprintProvider
	reporter   UsageReporter
}

// NewEnforcer builds an Enforcer from a limit provider and a footprint provider.
func NewEnforcer(limits LimitProvider, footprints FootprintProvider) *Enforcer {
	return &Enforcer{limits: limits, footprints: footprints}
}

// SetUsageReporter sets an optional reporter used by ReportUsage.
func (e *Enforcer) SetUsageReporter(r UsageReporter) {
	e.reporter = r
}

// ReportUsage computes the namespace's current footprint and reports it through
// the configured reporter. It is a no-op when no reporter is set. Best-effort:
// intended to be called asynchronously after a successful upload.
func (e *Enforcer) ReportUsage(ctx context.Context, namespace string) error {
	if e.reporter == nil {
		return nil
	}
	used, err := e.footprints.Footprint(ctx, namespace)
	if err != nil {
		return err
	}
	return e.reporter.ReportUsage(ctx, namespace, used)
}

// Check returns nil if a blob of `incoming` bytes may be admitted to namespace,
// ErrQuotaExceeded if it would exceed the quota, or another (fail-closed) error
// if the decision could not be made.
func (e *Enforcer) Check(ctx context.Context, namespace string, incoming int64) error {
	limit, err := e.limits.Limit(ctx, namespace)
	if err != nil {
		return fmt.Errorf("resolve quota limit: %w", err)
	}
	if limit <= 0 {
		return nil // no quota / unlimited
	}

	used, err := e.footprints.Footprint(ctx, namespace)
	if err != nil {
		return fmt.Errorf("resolve project footprint: %w", err)
	}

	if WouldExceed(used, incoming, limit) {
		return fmt.Errorf("%w: %d + %d > %d bytes", ErrQuotaExceeded, used, incoming, limit)
	}
	return nil
}
