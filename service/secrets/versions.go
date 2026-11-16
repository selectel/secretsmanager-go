package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
)

// CreateVersion stores a plain-text value as a new version, optionally making it current.
// Returned values remain base64 encoded, as with Get.
func (s Service) CreateVersion(ctx context.Context, key, value string, activate bool) (SecretVersion, error) {
	if value == "" {
		return SecretVersion{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptySecretValue,
			Desc: "field value in secret is empty",
		}
	}
	endpoint, err := s.versionsEndpoint(key)
	if err != nil {
		return SecretVersion{}, err
	}
	endpoint += "?activate=" + strconv.FormatBool(activate)
	request := struct {
		Value string `json:"value"`
	}{Value: base64.StdEncoding.EncodeToString([]byte(value))}
	var result SecretVersion
	err = s.versionRequest(ctx, http.MethodPost, endpoint, request, &result)
	return result, err
}

// ActivateVersion makes an existing secret version current.
func (s Service) ActivateVersion(ctx context.Context, key string, version uint64) (VersionMetadata, error) {
	endpoint, err := s.versionEndpoint(key, version, "activate")
	if err != nil {
		return VersionMetadata{}, err
	}
	var result VersionMetadata
	err = s.versionRequest(ctx, http.MethodPost, endpoint, nil, &result)
	return result, err
}

// GetVersion returns a specific secret version, with its value base64 encoded.
func (s Service) GetVersion(ctx context.Context, key string, version uint64) (SecretVersion, error) {
	endpoint, err := s.versionEndpoint(key, version)
	if err != nil {
		return SecretVersion{}, err
	}
	var result SecretVersion
	err = s.versionRequest(ctx, http.MethodGet, endpoint, nil, &result)
	return result, err
}

// ListVersions returns secret metadata and metadata for all its versions.
func (s Service) ListVersions(ctx context.Context, key string) (SecretVersions, error) {
	endpoint, err := s.versionsEndpoint(key)
	if err != nil {
		return SecretVersions{}, err
	}
	var result SecretVersions
	err = s.versionRequest(ctx, http.MethodGet, endpoint, nil, &result)
	return result, err
}

func (s Service) versionEndpoint(key string, version uint64, suffix ...string) (string, error) {
	if version == 0 {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrBadRequestStatusText,
			Desc: "version must be greater than zero",
		}
	}
	parts := append([]string{strconv.FormatUint(version, 10)}, suffix...)
	return s.versionsEndpoint(key, parts...)
}

func (s Service) versionsEndpoint(key string, suffix ...string) (string, error) {
	if key == "" {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptySecretName,
			Desc: "field name in secret is empty",
		}
	}
	parts := append([]string{apiVersion, url.PathEscape(key), "versions"}, suffix...)
	endpoint, err := url.JoinPath(s.apiURLSecrets, parts...)
	if err != nil {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}
	return endpoint, nil
}

func (s Service) versionRequest(ctx context.Context, method, endpoint string, request, result any) error {
	var body io.Reader
	if request != nil {
		data, err := json.Marshal(request)
		if err != nil {
			return secretsmanagererrors.Error{Err: secretsmanagererrors.ErrCannotMarshalSecretBody, Desc: err.Error()}
		}
		body = bytes.NewReader(data)
	}
	data, err := s.httpClient.DoRequest(ctx, method, endpoint, body)
	if err != nil {
		return err //nolint:wrapcheck // DoRequest wraps errors.
	}
	if err := json.Unmarshal(data, result); err != nil {
		return secretsmanagererrors.Error{Err: secretsmanagererrors.ErrCannotUnmarshalBody, Desc: err.Error()}
	}
	return nil
}
