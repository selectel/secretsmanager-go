package secretsmanager

import (
	"net/http"

	"github.com/selectel/secretsmanager-go/internal/auth"
	"github.com/selectel/secretsmanager-go/internal/httpclient"
	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
	"github.com/selectel/secretsmanager-go/service/certs"
	"github.com/selectel/secretsmanager-go/service/secrets"
)

const (
	// URL for working with secrets.
	defaultAPIURLSecrets = "https://cloud.api.selcloud.ru/secrets-manager/v1/" //nolint:gosec

	// URL for working with certificates.
	defaultAPIURLUserCertificates = "https://cloud.api.selcloud.ru/certificate-manager/v1/"
)

// Client — implements operations to work with the Secrets Manager API using the Keystone Token.
type Client struct {
	Secrets      *secrets.Service
	Certificates *certs.Service
	cfg          *config
}

type ClientOption func(*Client)

// AuthOpts is a helper structure used during client initialization.
// Depending on the data passed in the structure
// (like Keystone Token or newer that will be added in future)
// the required authentication structure will be selected.
type AuthOpts struct {
	KeystoneToken string
}

// WithAuthOpts is a functional parameter for SecretsManagerClient, used to set on of implementations of AuthType.
func WithAuthOpts(authOpts *AuthOpts) ClientOption {
	return func(c *Client) {
		c.cfg.authOpts = authOpts
	}
}

func WithCustomURLSecrets(url string) ClientOption {
	return func(c *Client) {
		c.cfg.APIURLSecrets = url
	}
}

func WithCustomURLCertificates(url string) ClientOption {
	return func(c *Client) {
		c.cfg.APIURLUserCertificates = url
	}
}

func WithCustomHTTPClient(customHTTPClient *http.Client) ClientOption {
	return func(c *Client) {
		c.cfg.customHTTPClient = customHTTPClient
	}
}

type config struct {
	APIURLSecrets          string
	APIURLUserCertificates string

	// AuthOpts contains data to authenticate against Selectel Secrets Manager API.
	authOpts         *AuthOpts
	customHTTPClient *http.Client
}

func defaultConfig() *config {
	return &config{
		APIURLSecrets:          defaultAPIURLSecrets,
		APIURLUserCertificates: defaultAPIURLUserCertificates,
	}
}

func New(options ...ClientOption) (*Client, error) {
	cl := &Client{
		cfg: defaultConfig(),
	}

	for _, option := range options {
		option(cl)
	}

	auth, err := newAuth(cl.cfg.authOpts)
	if err != nil {
		return nil, err
	}

	httpClient := httpclient.New(auth, cl.cfg.customHTTPClient)

	cl.Secrets = secrets.New(cl.cfg.APIURLSecrets, httpClient)
	cl.Certificates = certs.New(cl.cfg.APIURLUserCertificates, httpClient)

	return cl, nil
}

// newAuth — is a helper func, that checks if any of AuthOpts are passed into client
// and depending on given smcl.authOpts, decide which independent supported auth.Type to set.
func newAuth(authOpts *AuthOpts) (auth.Type, error) {
	if authOpts == nil {
		return nil, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrClientNoAuthOpts,
			Desc: "provided AuthOpts is empty",
		}
	}

	var authType auth.Type
	if len(authOpts.KeystoneToken) > 0 {
		ksta, err := auth.NewKeystoneTokenAuth(authOpts.KeystoneToken)
		if err != nil {
			return nil, secretsmanagererrors.Error{
				Err:  err,
				Desc: err.Error(),
			}
		}
		authType = ksta
	}

	return authType, nil
}
