package quota

import (
	"context"
	"errors"
	"testing"
)

type fakeLimits struct {
	limit int64
	err   error
}

func (f fakeLimits) Limit(_ context.Context, _ string) (int64, error) { return f.limit, f.err }

type fakeFootprint struct {
	used int64
	err  error
}

func (f fakeFootprint) Footprint(_ context.Context, _ string) (int64, error) { return f.used, f.err }

func TestEnforcerAllowsUnderLimit(t *testing.T) {
	e := NewEnforcer(fakeLimits{limit: 1000}, fakeFootprint{used: 500})
	if err := e.Check(context.Background(), "team-a", 100); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestEnforcerRejectsOverLimit(t *testing.T) {
	e := NewEnforcer(fakeLimits{limit: 1000}, fakeFootprint{used: 950})
	err := e.Check(context.Background(), "team-a", 100)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestEnforcerNoQuotaAllows(t *testing.T) {
	// limit 0 => unlimited; footprint should not even be consulted, but allow regardless
	e := NewEnforcer(fakeLimits{limit: 0}, fakeFootprint{used: 1 << 40})
	if err := e.Check(context.Background(), "team-a", 1<<30); err != nil {
		t.Fatalf("expected allow for no quota, got %v", err)
	}
}

func TestEnforcerFailsClosedOnLimitError(t *testing.T) {
	e := NewEnforcer(fakeLimits{err: errors.New("apiserver down")}, fakeFootprint{used: 0})
	err := e.Check(context.Background(), "team-a", 100)
	if err == nil || errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected a non-quota (fail-closed) error, got %v", err)
	}
}

func TestEnforcerFailsClosedOnFootprintError(t *testing.T) {
	e := NewEnforcer(fakeLimits{limit: 1000}, fakeFootprint{err: errors.New("storage error")})
	err := e.Check(context.Background(), "team-a", 100)
	if err == nil || errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected a non-quota (fail-closed) error, got %v", err)
	}
}

type fakeReporter struct {
	gotNS   string
	gotUsed int64
	called  bool
}

func (f *fakeReporter) ReportUsage(_ context.Context, ns string, used int64) error {
	f.called = true
	f.gotNS = ns
	f.gotUsed = used
	return nil
}

func TestEnforcerReportUsage(t *testing.T) {
	e := NewEnforcer(fakeLimits{limit: 1000}, fakeFootprint{used: 777})
	rep := &fakeReporter{}
	e.SetUsageReporter(rep)
	if err := e.ReportUsage(context.Background(), "team-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rep.called || rep.gotNS != "team-a" || rep.gotUsed != 777 {
		t.Fatalf("report: called=%v ns=%q used=%d", rep.called, rep.gotNS, rep.gotUsed)
	}
}

func TestEnforcerReportUsageNoReporterIsNoop(t *testing.T) {
	e := NewEnforcer(fakeLimits{limit: 1000}, fakeFootprint{used: 777})
	if err := e.ReportUsage(context.Background(), "team-a"); err != nil {
		t.Fatalf("expected no-op, got %v", err)
	}
}
