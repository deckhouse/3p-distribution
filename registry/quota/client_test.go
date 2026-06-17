package quota

import (
	"context"
	"net/http"
	"net/http/httptest"
	"io"
	"strings"
	"testing"
)

func TestLimitClientReturnsLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("namespace"); got != "team-a" {
			t.Errorf("namespace query = %q, want team-a", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"limit": 10485760}`))
	}))
	defer srv.Close()

	c := NewLimitClient(srv.URL, srv.Client())
	got, err := c.Limit(context.Background(), "team-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 10485760 {
		t.Fatalf("Limit=%d, want 10485760", got)
	}
}

func TestLimitClientNoQuotaReturnsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"limit": 0}`))
	}))
	defer srv.Close()

	c := NewLimitClient(srv.URL, srv.Client())
	got, err := c.Limit(context.Background(), "team-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Fatalf("Limit=%d, want 0 (unlimited)", got)
	}
}

func TestLimitClientServerErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewLimitClient(srv.URL, srv.Client())
	if _, err := c.Limit(context.Background(), "team-a"); err == nil {
		t.Fatalf("expected error on server 500, got nil")
	}
}

func TestLimitClientReportUsage(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewLimitClient(srv.URL, srv.Client())
	if err := c.ReportUsage(context.Background(), "team-a", 4096); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(gotBody, `"namespace":"team-a"`) || !strings.Contains(gotBody, `"used":4096`) {
		t.Fatalf("unexpected body: %s", gotBody)
	}
}
