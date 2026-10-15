package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCIRCLHashlookupBaseURL is the public CIRCL Hashlookup API endpoint.
	DefaultCIRCLHashlookupBaseURL = "https://hashlookup.circl.lu/lookup/sha256/"

	// DefaultHashlookupTimeout defines the strict per-request deadline.
	DefaultHashlookupTimeout = 3 * time.Second

	// DefaultHashlookupUserAgent identifies AppAudit to CIRCL.
	DefaultHashlookupUserAgent = "AppAudit-Auditor/2.1.0 (Security Scanner)"
)

// HashLookupResult represents a verified public distribution match returned by the CIRCL Hashlookup / NSRL service.
type HashLookupResult struct {
	Matched     bool   `json:"matched"`
	FileName    string `json:"file_name"`
	ProductName string `json:"product_name"`
	Source      string `json:"source"`
	Database    string `json:"database"`
	Trust       int    `json:"trust"`
}

type circlResponse struct {
	FileName    string `json:"FileName"`
	Source      string `json:"source"`
	DB          string `json:"db"`
	Trust       int    `json:"hashlookup:trust"`
	ProductCode struct {
		ProductName    string `json:"ProductName"`
		ProductVersion string `json:"ProductVersion"`
		MfgCode        any    `json:"MfgCode"`
	} `json:"ProductCode"`
	ProductName string `json:"ProductName"`
}

// HashLookupClient executes fault-tolerant, circuit-broken lookups against CIRCL Hashlookup.
type HashLookupClient struct {
	BaseURL        string
	HTTPClient     *http.Client
	MaxRetries     int
	BackoffDelay   time.Duration
	circuitTripped bool
	circuitReason  string
	failCount      int
	skippedCount   int
	cache          map[string]*HashLookupResult
	missing        map[string]bool
	mu             sync.RWMutex
}

// NewHashLookupClient initializes a HashLookupClient with default 3-second timeout and 1-retry policy.
func NewHashLookupClient(baseURL ...string) *HashLookupClient {
	url := DefaultCIRCLHashlookupBaseURL
	if envURL := os.Getenv("APPAUDIT_CIRCL_URL"); envURL != "" {
		url = envURL
	}
	if len(baseURL) > 0 && strings.TrimSpace(baseURL[0]) != "" {
		url = strings.TrimSpace(baseURL[0])
	}
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}

	return &HashLookupClient{
		BaseURL: url,
		HTTPClient: &http.Client{
			Timeout: DefaultHashlookupTimeout,
		},
		MaxRetries:   1,
		BackoffDelay: 500 * time.Millisecond,
		cache:        make(map[string]*HashLookupResult),
		missing:      make(map[string]bool),
	}
}

// IsDegraded reports whether the circuit breaker is currently open due to upstream outages.
func (c *HashLookupClient) IsDegraded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.circuitTripped
}

// SkippedCount returns the number of application lookups bypassed while the circuit breaker was open.
func (c *HashLookupClient) SkippedCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.skippedCount
}

// TripCircuit marks the client as degraded and logs a debug notice.
func (c *HashLookupClient) TripCircuit(reason ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := "upstream outage"
	if len(reason) > 0 && reason[0] != "" {
		r = reason[0]
	}
	if !c.circuitTripped {
		c.circuitTripped = true
		c.circuitReason = r
		fmt.Fprintf(os.Stderr, "[Tier 1.5B] Public hash API unreachable (%s); skipping to AI reasoning.\n", r)
	}
}

// CircuitReason returns the reason why the circuit was tripped.
func (c *HashLookupClient) CircuitReason() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.circuitReason
}

// ResetCircuit resets the circuit breaker to closed state.
func (c *HashLookupClient) ResetCircuit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.circuitTripped = false
	c.circuitReason = ""
	c.failCount = 0
	c.skippedCount = 0
}

// LookupSHA256 queries the CIRCL Hashlookup API for the given SHA-256 hash.
// If the circuit breaker is open, returns immediately with (nil, false, nil).
// Implements 1 retry on 5xx or network timeout, fail-fast on 404, and opens circuit on consecutive outages.
func (c *HashLookupClient) LookupSHA256(ctx context.Context, sha256 string) (*HashLookupResult, bool, error) {
	c.mu.Lock()
	if c.circuitTripped {
		c.skippedCount++
		c.mu.Unlock()
		return nil, false, nil
	}
	c.mu.Unlock()

	cleanHash := strings.ToLower(strings.TrimSpace(sha256))
	if cleanHash == "" || len(cleanHash) != 64 {
		return nil, false, nil
	}

	c.mu.RLock()
	if c.circuitTripped {
		c.mu.RUnlock()
		return nil, false, nil
	}
	if cached, ok := c.cache[cleanHash]; ok {
		c.mu.RUnlock()
		return cached, true, nil
	}
	if c.missing[cleanHash] {
		c.mu.RUnlock()
		return nil, false, nil
	}
	c.mu.RUnlock()

	reqURL := c.BaseURL + cleanHash

	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(c.BackoffDelay):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, false, err
		}
		httpReq.Header.Set("User-Agent", DefaultHashlookupUserAgent)
		httpReq.Header.Set("Accept", "application/json")

		resp, err := c.HTTPClient.Do(httpReq)
		if err != nil {
			lastErr = err
			c.mu.Lock()
			c.failCount++
			if c.failCount >= 2 {
				c.mu.Unlock()
				c.TripCircuit()
				return nil, false, err
			}
			c.mu.Unlock()
			continue
		}

		body, rErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rErr != nil {
			lastErr = rErr
			continue
		}

		// 404 Not Found: Binary not present in public database (Fail-fast, not an error)
		if resp.StatusCode == http.StatusNotFound {
			c.mu.Lock()
			c.failCount = 0 // Successful communication with API
			c.missing[cleanHash] = true
			c.mu.Unlock()
			return nil, false, nil
		}

		// 429 Too Many Requests: Upstream rate limit reached, trip circuit immediately
		if resp.StatusCode == http.StatusTooManyRequests {
			c.TripCircuit("429 Too Many Requests")
			return nil, false, nil
		}

		// 5xx Server Error: Retry once, then trip circuit if persistent
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("CIRCL Hashlookup HTTP %d", resp.StatusCode)
			c.mu.Lock()
			c.failCount++
			if c.failCount >= 2 {
				c.mu.Unlock()
				c.TripCircuit("5xx server error")
				return nil, false, lastErr
			}
			c.mu.Unlock()
			continue
		}

		if resp.StatusCode == http.StatusOK {
			c.mu.Lock()
			c.failCount = 0
			c.mu.Unlock()

			var cr circlResponse
			if err := json.Unmarshal(body, &cr); err != nil {
				return nil, false, fmt.Errorf("failed to decode CIRCL response: %w", err)
			}

			prod := cr.ProductCode.ProductName
			if prod == "" {
				prod = cr.ProductName
			}
			if prod == "" {
				prod = cr.FileName
			}

			src := cr.Source
			if src == "" {
				src = cr.DB
			}

			result := &HashLookupResult{
				Matched:     true,
				FileName:    cr.FileName,
				ProductName: prod,
				Source:      src,
				Database:    cr.DB,
				Trust:       cr.Trust,
			}
			c.mu.Lock()
			c.cache[cleanHash] = result
			c.mu.Unlock()

			return result, true, nil
		}

		lastErr = fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
	}

	return nil, false, lastErr
}
