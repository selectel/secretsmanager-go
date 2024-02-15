package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/selectel/secretsmanager-go/internal/auth"
	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
)

const (
	// appName represents an application name.
	appName = "knox-go"

	// appVersion represents an application version.
	appVersion = "0.1.0"

	// userAgent contains a basic User-Agent that will be used in all requests.
	userAgent = appName + "/" + appVersion
)

const ( // defaultHTTPTimeout represents the default timeout (in seconds) for HTTP requests.
	defaultHTTPTimeout = 120

	// defaultMaxIdleConns represents the maximum number of idle (keep-alive) connections.
	defaultMaxIdleConns = 100

	// defaultIdleConnTimeout represents the maximum amount of time an idle (keep-alive) connection will remain
	// idle before closing itself.
	defaultIdleConnTimeout = 100

	// defaultTLSHandshakeTimeout represents the default timeout (in seconds) for TLS handshake.
	defaultTLSHandshakeTimeout = 60

	// defaultExpectContinueTimeout represents the default amount of time to wait for a server's first
	// response headers.
	defaultExpectContinueTimeout = 1
)

type HTTPClient struct {
	*http.Client
	Auth auth.Type
}

func New(auth auth.Type, httpClient *http.Client) *HTTPClient {
	if httpClient == nil {
		httpClient = newHTTPClient()
	}

	return &HTTPClient{
		Client: httpClient,
		Auth:   auth,
	}
}

// DoRequest — is a helper method, to reduce repeated code.
func (cl *HTTPClient) DoRequest(ctx context.Context, method, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrInternalAppError,
			Desc: err.Error(),
		}
	}

	req.Header.Set("X-Auth-Token", cl.Auth.GetKeystoneToken())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return nil, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrInternalAppError,
			Desc: err.Error(),
		}
	}
	defer resp.Body.Close()

	err = hasBackendError(resp)
	if err != nil {
		return nil, err
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotReadBody,
			Desc: err.Error(),
		}
	}
	return respBody, nil
}

// hasBackendError is a helper function to returning an error from backend
// if StatusCode is either StatusUnauthorized or >= 400.
func hasBackendError(resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrAuthTokenUnathorized,
			Desc: secretsmanagererrors.AuthErrorCode,
		}
	}

	if resp.StatusCode >= 400 {
		errBodyText, err := io.ReadAll(resp.Body)
		if err != nil {
			return secretsmanagererrors.Error{
				Err:  secretsmanagererrors.ErrCannotReadBody,
				Desc: err.Error(),
			}
		}

		var er secretsmanagererrors.ErrResponse
		err = json.Unmarshal(errBodyText, &er)
		if err != nil {
			return secretsmanagererrors.Error{
				Err:  secretsmanagererrors.ErrInternalAppError,
				Desc: err.Error(),
			}
		}

		if e := secretsmanagererrors.GetError(er.StatusText); e != nil {
			return secretsmanagererrors.Error{Err: e, Desc: er.ErrorText}
		}

		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrUnknown,
			Desc: fmt.Sprintf("%s -- %s", er.StatusText, er.StatusText),
		}
	}
	return nil
}

// newHTTPClient returns a reference to an initialized and configured HTTP client.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   defaultHTTPTimeout * time.Second,
		Transport: newHTTPTransport(),
	}
}

// newHTTPTransport returns a reference to an initialized and configured HTTP transport.
func newHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          defaultMaxIdleConns,
		IdleConnTimeout:       defaultIdleConnTimeout * time.Second,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout * time.Second,
		ExpectContinueTimeout: defaultExpectContinueTimeout * time.Second,
	}
}
