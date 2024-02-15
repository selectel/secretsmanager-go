package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/selectel/secretsmanager-go/internal/httpclient"
	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
)

// Service implements Secrets Manager that is responsible for handling certificates operations.
type Service struct {
	apiURLUserCertificates string
	httpClient             *httpclient.HTTPClient
}

func New(url string, client *httpclient.HTTPClient) *Service {
	return &Service{
		apiURLUserCertificates: url,
		httpClient:             client,
	}
}

func (s Service) Delete(ctx context.Context, id string) error {
	if len(id) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	_, err = s.httpClient.DoRequest(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return nil
}

func (s Service) Get(ctx context.Context, id string) (Certificate, error) {
	if len(id) == 0 {
		return Certificate{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id)
	if err != nil {
		return Certificate{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Certificate{}, err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	var crt Certificate
	err = json.Unmarshal(respBody, &crt)
	if err != nil {
		return Certificate{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotUnmarshalBody,
			Desc: err.Error(),
		}
	}
	return crt, nil
}

func (s Service) UpdateVersion(ctx context.Context, id string, pem UpdateCertificateVersionRequest) error {
	if len(id) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	err := validatePEM(pem.Pem)
	if err != nil {
		return err
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	marshalled, err := json.Marshal(pem)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotMarshalCertificateBody,
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

func (s Service) UpdateName(ctx context.Context, id, name string) error {
	if len(id) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	if len(name) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateName,
			Desc: "trying to update a certificate with empty name",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	nn := UpdateCertificateNameRequest{
		Name: name,
	}

	marshalled, err := json.Marshal(nn)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotMarshalCertificateBody,
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

func (s Service) GetPublicCerts(ctx context.Context, id string) (string, error) {
	if len(id) == 0 {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id, "ca_chain")
	if err != nil {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return string(respBody), nil
}

func (s Service) RemoveConsumers(ctx context.Context, id string, consumers RemoveConsumersRequest) error {
	if len(id) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id, "consumers")
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	marshalled, err := json.Marshal(consumers)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotMarshalCertificateBody,
			Desc: err.Error(),
		}
	}

	reqBody := bytes.NewReader(marshalled)

	_, err = s.httpClient.DoRequest(ctx, http.MethodDelete, endpoint, reqBody)
	if err != nil {
		return err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return nil
}

func (s Service) AddConsumers(ctx context.Context, id string, consumers AddConsumersRequest) error {
	if len(id) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id, "consumers")
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	marshalled, err := json.Marshal(consumers)
	if err != nil {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotMarshalCertificateBody,
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

func (s Service) GetPKCS12Bundle(ctx context.Context, id string) ([]byte, error) {
	if len(id) == 0 {
		return []byte{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id, "p12")
	if err != nil {
		return []byte{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return []byte{}, err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return respBody, nil
}

func (s Service) GetPrivateKey(ctx context.Context, id string) (string, error) {
	if len(id) == 0 {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateID,
			Desc: "empty certificate id",
		}
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "cert", id, "private_key")
	if err != nil {
		return "", secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	return string(respBody), nil
}

func (s Service) List(ctx context.Context) (GetCertificatesResponse, error) {
	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "certs")
	if err != nil {
		return GetCertificatesResponse{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return GetCertificatesResponse{}, err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	var crts GetCertificatesResponse
	err = json.Unmarshal(respBody, &crts)
	if err != nil {
		return GetCertificatesResponse{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotUnmarshalBody,
			Desc: err.Error(),
		}
	}
	return crts, nil
}

func (s Service) Create(ctx context.Context, ucr CreateCertificateRequest) (Certificate, error) {
	err := validateCertificate(ucr)
	if err != nil {
		return Certificate{}, err
	}

	endpoint, err := url.JoinPath(s.apiURLUserCertificates, "certs")
	if err != nil {
		return Certificate{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotFormatEndpoint,
			Desc: err.Error(),
		}
	}

	marshalled, err := json.Marshal(ucr)
	if err != nil {
		return Certificate{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotMarshalCertificateBody,
			Desc: err.Error(),
		}
	}
	reqBody := bytes.NewReader(marshalled)

	respBody, err := s.httpClient.DoRequest(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		return Certificate{}, err //nolint:wrapcheck // DoRequest already wraps the error.
	}

	var crt Certificate
	err = json.Unmarshal(respBody, &crt)
	if err != nil {
		return Certificate{}, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrCannotUnmarshalBody,
			Desc: err.Error(),
		}
	}
	return crt, nil
}

func validateCertificate(ucr CreateCertificateRequest) error {
	if len(ucr.Name) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyCertificateName,
			Desc: "trying to create a certificate with empty name",
		}
	}

	err := validatePEM(ucr.Pem)
	if err != nil {
		return err
	}

	return nil
}

func validatePEM(pem Pem) error {
	if len(pem.Certificates) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyPEMCertificate,
			Desc: "trying to create a certificate with empty PEM certificate(s)",
		}
	}

	if len(pem.PrivateKey) == 0 {
		return secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrEmptyPEMPrivateKey,
			Desc: "trying to create a certificate with empty PEM private key",
		}
	}

	return nil
}
