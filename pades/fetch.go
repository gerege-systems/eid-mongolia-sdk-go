package pades

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DefaultTSAURL — нийтийн RFC 3161 TSA (CA-ийн /.well-known/eid endpoints.tsa).
const DefaultTSAURL = "https://tsa.timeserver.mn/"

const (
	httpTimeout     = 10 * time.Second
	maxHTTPResponse = 4 << 20
)

// defaultHTTPClient — timeout 10 с, redirect дагахгүй.
func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: httpTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type fetcher struct {
	client *http.Client
	cache  map[string][]byte // GET (CRL) URL → хариу
}

func newFetcher(c *http.Client) *fetcher {
	if c == nil {
		c = defaultHTTPClient()
	}
	return &fetcher{client: c, cache: map[string][]byte{}}
}

// target — зөвхөн http/https.
func (f *fetcher) target(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https", "http":
	default:
		return "", fmt.Errorf("URL scheme %q дэмжигдэхгүй", u.Scheme)
	}
	return u.String(), nil
}

// do — нэг HTTP хүсэлт; 200 биш эсвэл 4 MiB-аас их бол алдаа.
func (f *fetcher) do(ctx context.Context, method, raw, contentType string, body []byte) ([]byte, error) {
	target, err := f.target(raw)
	if err != nil {
		return nil, err
	}
	if method == http.MethodGet {
		if b, ok := f.cache[target]; ok {
			return b, nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := f.client.Do(req) // #nosec G107 -- URL нь гэрчилгээний AIA/CDP эсвэл тохируулсан TSA
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponse+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || len(out) > maxHTTPResponse {
		return nil, fmt.Errorf("%s: HTTP %d", target, resp.StatusCode)
	}
	if method == http.MethodGet {
		f.cache[target] = out
	}
	return out, nil
}
