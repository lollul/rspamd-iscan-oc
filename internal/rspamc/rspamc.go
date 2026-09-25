package rspamc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"
)

const defaultHTTPTimeout = 2 * time.Minute

// HTTPStatusError reports a non-success response from Rspamd.
type HTTPStatusError struct {
	StatusCode int
	Status     string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("rspamd request failed with status: %s", e.Status)
}

// Retryable reports whether the status represents a temporary Rspamd failure.
func (e *HTTPStatusError) Retryable() bool {
	return e.StatusCode == http.StatusRequestTimeout ||
		e.StatusCode == http.StatusTooEarly ||
		e.StatusCode == http.StatusTooManyRequests ||
		e.StatusCode >= 500
}

// RetryKey provides a stable retry category for status errors.
func (e *HTTPStatusError) RetryKey() string {
	return fmt.Sprintf("http-%d", e.StatusCode)
}

type Client struct {
	checkURL   string
	hamURL     string
	spamURL    string
	logger     *slog.Logger
	password   string
	httpClient *http.Client
}

func New(logger *slog.Logger, url, password string, timeouts ...time.Duration) *Client {
	timeout := defaultHTTPTimeout
	if len(timeouts) > 0 && timeouts[0] > 0 {
		timeout = timeouts[0]
	}

	return &Client{
		checkURL:   url + "/checkv2",
		hamURL:     url + "/learnham",
		spamURL:    url + "/learnspam",
		logger:     logger.WithGroup("rspamc").With("server", url),
		password:   password,
		httpClient: &http.Client{Timeout: timeout},
	}
}

func (c *Client) logReq(ctx context.Context, req *http.Request) {
	if !c.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}

	reqDump, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		c.logger.Warn("converting http request to printable representation failed", "error", err)
		return
	}

	c.logger.Debug("sending http-request (body and password are omitted)", "request", string(reqDump))
}

func (c *Client) logResp(ctx context.Context, resp *http.Response) {
	if !c.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}

	respDump, err := httputil.DumpResponse(resp, false)
	if err != nil {
		c.logger.Warn(
			"converting http response to printable representation failed",
			"error", err,
		)
		return
	}

	c.logger.Debug("received http-response (body omitted)", "response", string(respDump))
}

func (c *Client) sendRequest(ctx context.Context, url string, msg io.Reader, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, msg)
	if err != nil {
		return fmt.Errorf("creating rspamd request failed: %w", err)
	}

	c.logReq(ctx, req)

	req.Header.Add("password", c.password)

	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending rspamd request failed: %w", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512*1024))
		_ = resp.Body.Close()
	}()

	c.logResp(ctx, resp)

	if result == nil {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		return &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}

	if resp.StatusCode != http.StatusOK {
		return &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}

	const contentTypeJSON = "application/json"
	ctype := resp.Header.Get("Content-Type")
	if ctype != contentTypeJSON {
		return fmt.Errorf("got response with content-type: %q, expecting: %q", ctype, contentTypeJSON)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decoding rspamd response failed: %w", err)
	}

	return nil
}

func (c *Client) Check(ctx context.Context, msg io.Reader) (*CheckResult, error) {
	var result CheckResult
	// wrap in NopCloser to prevent that http.NewRequest closes the reader,
	// it is not responsible for closing it, the caller is
	err := c.sendRequest(ctx, c.checkURL, io.NopCloser(msg), &result)
	if err != nil {
		return nil, err
	}
	return &result, err
}

func (c *Client) Ham(ctx context.Context, msg io.Reader) error {
	// resp code 208 == already learned, returns a json with an "error"
	// field
	return c.sendRequest(ctx, c.hamURL, msg, nil)
}

func (c *Client) Spam(ctx context.Context, msg io.Reader) error {
	return c.sendRequest(ctx, c.spamURL, msg, nil)
}

type CheckResult struct {
	Action    string             `json:"action"`
	Score     float32            `json:"score"`
	IsSkipped bool               `json:"is_skipped"`
	Symbols   map[string]*Symbol `json:"symbols"`
	Subject   string             `json:"subject,omitempty"`
}

// https://docs.rspamd.com/developers/protocol#protocol-basics
type Symbol struct {
	Name  string  `json:"name"`
	Score float32 `json:"score"`
}
