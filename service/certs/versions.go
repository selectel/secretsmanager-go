package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
)

// CreateVersion uploads a certificate version, optionally making it current.
func (s Service) CreateVersion(
	ctx context.Context, id string, request UpdateCertificateVersionRequest, activate bool,
) (Certificate, error) {
	if err := validatePEM(request.Pem); err != nil {
		return Certificate{}, err
	}
	endpoint, err := s.certificateEndpoint(id, "versions")
	if err != nil {
		return Certificate{}, err
	}
	endpoint += "?activate=" + strconv.FormatBool(activate)
	var result Certificate
	err = s.certificateRequest(ctx, http.MethodPost, endpoint, request, &result)
	return result, err
}

// ActivateVersion makes an existing certificate version current.
func (s Service) ActivateVersion(ctx context.Context, id string, version uint64) (Certificate, error) {
	endpoint, err := s.versionEndpoint(id, version, "activate")
	if err != nil {
		return Certificate{}, err
	}
	var result Certificate
	err = s.certificateRequest(ctx, http.MethodPost, endpoint, nil, &result)
	return result, err
}

// GetVersion returns a specific certificate version.
func (s Service) GetVersion(ctx context.Context, id string, version uint64) (Certificate, error) {
	endpoint, err := s.versionEndpoint(id, version)
	if err != nil {
		return Certificate{}, err
	}
	var result Certificate
	err = s.certificateRequest(ctx, http.MethodGet, endpoint, nil, &result)
	return result, err
}

// ListVersions returns metadata for all certificate versions.
func (s Service) ListVersions(ctx context.Context, id string) (ListVersionsResponse, error) {
	endpoint, err := s.certificateEndpoint(id, "versions")
	if err != nil {
		return ListVersionsResponse{}, err
	}
	var result ListVersionsResponse
	err = s.certificateRequest(ctx, http.MethodGet, endpoint, nil, &result)
	return result, err
}

// GetVersionPrivateKey returns the PEM private key of a certificate version.
func (s Service) GetVersionPrivateKey(ctx context.Context, id string, version uint64) (string, error) {
	body, err := s.getVersionContent(ctx, id, version, "private_key")
	return string(body), err
}

// GetVersionPublicCerts returns the PEM certificate chain of a certificate version.
func (s Service) GetVersionPublicCerts(ctx context.Context, id string, version uint64) (string, error) {
	body, err := s.getVersionContent(ctx, id, version, "ca_chain")
	return string(body), err
}

// GetVersionPKCS12Bundle returns the binary PKCS#12 bundle of a certificate version.
func (s Service) GetVersionPKCS12Bundle(ctx context.Context, id string, version uint64) ([]byte, error) {
	return s.getVersionContent(ctx, id, version, "p12")
}

func (s Service) getVersionContent(ctx context.Context, id string, version uint64, content string) ([]byte, error) {
	endpoint, err := s.versionEndpoint(id, version, content)
	if err != nil {
		return nil, err
	}
	return s.httpClient.DoRequest(ctx, http.MethodGet, endpoint, nil) //nolint:wrapcheck // DoRequest wraps errors.
}

func (s Service) versionEndpoint(id string, version uint64, suffix ...string) (string, error) {
	if version == 0 {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrBadRequestStatusText,
			Desc: "version must be greater than zero",
		}
	}
	parts := append([]string{"versions", strconv.FormatUint(version, 10)}, suffix...)
	return s.certificateEndpoint(id, parts...)
}

func (s Service) certificateEndpoint(id string, suffix ...string) (string, error) {
	if id == "" {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}
	parts := append([]string{apiVersion, "cert", url.PathEscape(id)}, suffix...)
	endpoint, err := url.JoinPath(s.apiURLUserCertificates, parts...)
	if err != nil {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}
	return endpoint, nil
}

func (s Service) certificateRequest(ctx context.Context, method, endpoint string, request, result any) error {
	var body io.Reader
	if request != nil {
		data, err := json.Marshal(request)
		if err != nil {
			return secretsmanagererrors.Error{
				Err:  secretsmanagererrors.ErrCannotMarshalCertificateBody,
				Desc: err.Error(),
			}
		}
		body = bytes.NewReader(data)
	}
	data, err := s.httpClient.DoRequest(ctx, method, endpoint, body)
	if err != nil {
		return err //nolint:wrapcheck // DoRequest wraps errors.
	}
	if result != nil {
		if err := json.Unmarshal(data, result); err != nil {
			return secretsmanagererrors.Error{Err: secretsmanagererrors.ErrCannotUnmarshalBody, Desc: err.Error()}
		}
	}
	return nil
}
