package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/selectel/secretsmanager-go/internal/httpclient"
	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
)

const apiVersion = "v1"

// Service implements Secrets Manager part that is responsible for handling secrets operations.
type Service struct {
	apiURLSecrets string
	httpClient    *httpclient.HTTPClient
}

func New(url string, client *httpclient.HTTPClient) *Service {
	return &Service{
		apiURLSecrets: url,
		httpClient:    client,
	}
}

func (s Service) List(ctx context.Context) (Secrets, error) {
	rawEndpoint, err := url.JoinPath(s.apiURLSecrets, apiVersion)
	if err != nil {
		return Secrets{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	endpoint, err := url.Parse(rawEndpoint)
	if err != nil {
		return Secrets{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	q := endpoint.Query()
	q.Add("list", "")
	endpoint.RawQuery = q.Encode()

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Secrets{}, err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	var sc Secrets
	err = json.Unmarshal(respBody, &sc)
	if err != nil {
		return Secrets{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotUnmarshalBody,
			Desc: err.Error(),
		}
	}
	return sc, nil
}

func (s Service) Delete(ctx context.Context, key string) error {
	if len(key) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptySecretName,
			Desc: "field name in secret is empty",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLSecrets, apiVersion, key)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrInternalAppError,
			Desc: err.Error(),
		}
	}
	_, err = s.httpClient.DoRequest(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return nil
}

func (s Service) Get(ctx context.Context, key string) (Secret, error) {
	if len(key) == 0 {
		return Secret{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptySecretName,
			Desc: "field name in secret is empty",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLSecrets, apiVersion, key)
	if err != nil {
		return Secret{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Secret{}, err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	var sc Secret
	err = json.Unmarshal(respBody, &sc)
	if err != nil {
		return Secret{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotUnmarshalBody,
			Desc: err.Error(),
		}
	}

	return sc, nil
}

func (s Service) Update(ctx context.Context, usc UserSecret) error {
	if len(usc.Key) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptySecretName,
			Desc: "field name in secret is empty",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLSecrets, apiVersion, usc.Key)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	marshalled, err := json.Marshal(usc)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotMarshalSecretBody,
			Desc: err.Error(),
		}
	}

	reqBody := bytes.NewReader(marshalled)

	_, err = s.httpClient.DoRequest(ctx, http.MethodPut, endpoint, reqBody)
	if err != nil {
		return err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return nil
}

func (s Service) Create(ctx context.Context, usc UserSecret) error {
	if len(usc.Key) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptySecretName,
			Desc: "field name in secret is empty",
		}
	}

	if len(usc.Value) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptySecretValue,
			Desc: "field value in secret is empty",
		}
	}
	usc.Value = base64.StdEncoding.EncodeToString([]byte(usc.Value))

	endpoint, err := url.JoinPath(s.apiURLSecrets, apiVersion, usc.Key)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	marshalled, err := json.Marshal(usc)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotMarshalSecretBody,
			Desc: err.Error(),
		}
	}

	reqBody := bytes.NewReader(marshalled)
	_, err = s.httpClient.DoRequest(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		return err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return nil
}
