package quota

import (
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
