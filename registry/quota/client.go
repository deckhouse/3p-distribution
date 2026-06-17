package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// LimitClient fetches a namespace's quota limit from the module apiserver.
type LimitClient struct {
	baseURL string
	http    *http.Client
}

// NewLimitClient returns a LimitClient targeting baseURL (e.g.
// "https://apiserver.d8-payload-registry.svc") using the given HTTP client
// (configured with the appropriate CA / client certificate).
func NewLimitClient(baseURL string, httpClient *http.Client) *LimitClient {
	return &LimitClient{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

type limitResponse struct {
	Limit int64 `json:"limit"`
}

// Limit returns the quota limit in bytes for the namespace. A return of 0 means
// "no quota / unlimited". A non-nil error means the limit could not be
// determined; callers enforcing a hard quota must fail closed.
func (c *LimitClient) Limit(ctx context.Context, namespace string) (int64, error) {
	u := fmt.Sprintf("%s/quota/limit?namespace=%s", c.baseURL, url.QueryEscape(namespace))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, fmt.Errorf("build quota limit request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("call quota limit endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("quota limit endpoint returned status %d", resp.StatusCode)
	}

	var lr limitResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return 0, fmt.Errorf("decode quota limit response: %w", err)
	}
	return lr.Limit, nil
}

type usageReport struct {
	Namespace string `json:"namespace"`
	Used      int64  `json:"used"`
}

// ReportUsage reports a namespace's current usage (bytes) to the apiserver so it
// can be surfaced in the PayloadRegistryQuota status. Best-effort: errors are
// returned for logging but should not fail the originating request.
func (c *LimitClient) ReportUsage(ctx context.Context, namespace string, used int64) error {
	body, err := json.Marshal(usageReport{Namespace: namespace, Used: used})
	if err != nil {
		return fmt.Errorf("marshal usage report: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/quota/usage", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build usage report request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call usage report endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("usage report endpoint returned status %d", resp.StatusCode)
	}
	return nil
}
