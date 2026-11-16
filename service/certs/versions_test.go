package certs_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/selectel/secretsmanager-go/internal/auth"
	"github.com/selectel/secretsmanager-go/internal/httpclient"
	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
	"github.com/selectel/secretsmanager-go/service/certs"
)

func versionService(t *testing.T, handler http.HandlerFunc) *certs.Service {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	authenticator, err := auth.NewKeystoneTokenAuth("dummy")
	require.NoError(t, err)
	return certs.New(server.URL, httpclient.New(authenticator, server.Client()))
}

func TestCreateCertificateVersion(t *testing.T) {
	for _, activate := range []bool{false, true} {
		t.Run(strconv.FormatBool(activate), func(t *testing.T) {
			request := certs.UpdateCertificateVersionRequest{
				Pem: certs.Pem{Certificates: []string{testDummyPEMCert}, PrivateKey: testDummyPEMPrivateKey},
			}
			service := versionService(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/v1/cert/cert%2F%25%3F%23/versions", r.URL.EscapedPath())
				assert.Equal(t, strconv.FormatBool(activate), r.URL.Query().Get("activate"))
				var payload certs.UpdateCertificateVersionRequest
				require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
				assert.Equal(t, request, payload)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"cert/?#","version":42}`))
			})
			result, err := service.CreateVersion(context.Background(), "cert/%?#", request, activate)
			require.NoError(t, err)
			assert.EqualValues(t, 42, result.Version)
		})
	}
}

func TestCertificateVersionRoutes(t *testing.T) {
	ctx := context.Background()
	service := versionService(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/cert/cert/versions":
			assert.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write([]byte(`{"versions":[{"version_id":42,"created_at":"2026-11-13T10:00:00Z",` +
				`"expires_at":null,"is_current":true},{"version_id":41,"expires_at":"2027-01-01T00:00:00Z"}]}`))
		case "/v1/cert/cert/versions/42", "/v1/cert/cert/versions/42/activate":
			method := http.MethodGet
			if r.URL.Path == "/v1/cert/cert/versions/42/activate" {
				method = http.MethodPost
			}
			assert.Equal(t, method, r.Method)
			_, _ = w.Write([]byte(`{"id":"cert","version":42,"consumers":[{"metadata":{"ready":true}}]}`))
		case "/v1/cert/cert/versions/42/private_key", "/v1/cert/cert/versions/42/ca_chain":
			assert.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write([]byte("PEM contents\n"))
		case "/v1/cert/cert/versions/42/p12":
			assert.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write([]byte{0, 255, 1, 128})
		default:
			t.Errorf("unexpected route: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	versions, err := service.ListVersions(ctx, "cert")
	require.NoError(t, err)
	require.Len(t, versions.Versions, 2)
	assert.Equal(t, uint64(42), versions.Versions[0].VersionID)
	assert.Equal(t, "2026-11-13T10:00:00Z", versions.Versions[0].CreatedAt)
	assert.True(t, versions.Versions[0].IsCurrent)
	assert.Nil(t, versions.Versions[0].ExpiresAt)
	require.NotNil(t, versions.Versions[1].ExpiresAt)
	assert.Equal(t, "2027-01-01T00:00:00Z", *versions.Versions[1].ExpiresAt)
	certificate, err := service.GetVersion(ctx, "cert", 42)
	require.NoError(t, err)
	assert.EqualValues(t, 42, certificate.Version)
	assert.Equal(t, map[string]any{"ready": true}, certificate.Consumers[0].Metadata)
	certificate, err = service.ActivateVersion(ctx, "cert", 42)
	require.NoError(t, err)
	assert.EqualValues(t, 42, certificate.Version)
	privateKey, err := service.GetVersionPrivateKey(ctx, "cert", 42)
	require.NoError(t, err)
	assert.Equal(t, "PEM contents\n", privateKey)
	chain, err := service.GetVersionPublicCerts(ctx, "cert", 42)
	require.NoError(t, err)
	assert.Equal(t, "PEM contents\n", chain)
	bundle, err := service.GetVersionPKCS12Bundle(ctx, "cert", 42)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 255, 1, 128}, bundle)
}

func TestCertificateVersionErrors(t *testing.T) {
	request := certs.UpdateCertificateVersionRequest{Pem: certs.Pem{Certificates: []string{"cert"}, PrivateKey: "key"}}
	calls := map[string]func(*certs.Service, string, uint64) error{
		"create": func(s *certs.Service, id string, _ uint64) error {
			_, err := s.CreateVersion(context.Background(), id, request, false)
			if err != nil {
				return fmt.Errorf("create certificate version: %w", err)
			}
			return nil
		},
		"list": func(s *certs.Service, id string, _ uint64) error {
			_, err := s.ListVersions(context.Background(), id)
			if err != nil {
				return fmt.Errorf("list certificate versions: %w", err)
			}
			return nil
		},
		"get": func(s *certs.Service, id string, version uint64) error {
			_, err := s.GetVersion(context.Background(), id, version)
			if err != nil {
				return fmt.Errorf("get certificate version: %w", err)
			}
			return nil
		},
		"activate": func(s *certs.Service, id string, version uint64) error {
			_, err := s.ActivateVersion(context.Background(), id, version)
			if err != nil {
				return fmt.Errorf("activate certificate version: %w", err)
			}
			return nil
		},
		"private_key": func(s *certs.Service, id string, version uint64) error {
			_, err := s.GetVersionPrivateKey(context.Background(), id, version)
			if err != nil {
				return fmt.Errorf("get certificate version private key: %w", err)
			}
			return nil
		},
		"ca_chain": func(s *certs.Service, id string, version uint64) error {
			_, err := s.GetVersionPublicCerts(context.Background(), id, version)
			if err != nil {
				return fmt.Errorf("get certificate version public certificates: %w", err)
			}
			return nil
		},
		"p12": func(s *certs.Service, id string, version uint64) error {
			_, err := s.GetVersionPKCS12Bundle(context.Background(), id, version)
			if err != nil {
				return fmt.Errorf("get certificate version PKCS12 bundle: %w", err)
			}
			return nil
		},
	}
	service := versionService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status_text":"NOT_FOUND","error_text":"missing version"}`))
	})
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call(service, "", 42), secretsmanagererrors.ErrEmptyCertificateID)
			require.ErrorIs(t, call(service, "cert", 42), secretsmanagererrors.ErrNotFoundStatusText)
			if name != "create" && name != "list" {
				require.ErrorIs(t, call(service, "cert", 0), secretsmanagererrors.ErrBadRequestStatusText)
			}
		})
	}
	_, err := service.CreateVersion(context.Background(), "cert", certs.UpdateCertificateVersionRequest{}, false)
	require.ErrorIs(t, err, secretsmanagererrors.ErrEmptyPEMCertificate)
	request.Pem.PrivateKey = ""
	_, err = service.CreateVersion(context.Background(), "cert", request, false)
	require.ErrorIs(t, err, secretsmanagererrors.ErrEmptyPEMPrivateKey)
	request.Pem.PrivateKey = "key"
	malformed := versionService(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("invalid JSON"))
	})
	for _, name := range []string{"create", "list", "get", "activate"} {
		require.ErrorIs(t, calls[name](malformed, "cert", 42), secretsmanagererrors.ErrCannotUnmarshalBody)
	}
}

func TestConsumerMetadata(t *testing.T) {
	for _, metadata := range []any{nil, map[string]any{"deployment": "blue", "ready": true}} {
		service := versionService(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, "/v1/cert/cert/consumers/type%2Fone/region%3F/id%2F%25%3F%23%20value", r.URL.EscapedPath())
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			assert.Equal(t, map[string]any{"metadata": metadata}, payload)
			w.WriteHeader(http.StatusNoContent)
		})
		err := service.UpdateConsumerMetadata(
			context.Background(), "cert", "type/one", "region?", "id/%?# value", metadata,
		)
		require.NoError(t, err)
	}
}

func TestAddConsumerMetadataAndRead(t *testing.T) {
	metadata := map[string]any{"deployment": "blue"}
	service := versionService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			assert.Equal(t, "/v1/cert/cert/consumers", r.URL.Path)
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			assert.Equal(t, map[string]any{
				"consumers": []any{
					map[string]any{
						"id": "id", "region": "region", "type": "type",
						"metadata": map[string]any{"deployment": "blue"},
					},
					map[string]any{"id": "without-metadata", "region": "region", "type": "type"},
				},
			}, payload)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"id":"cert","consumers":[{"metadata":{"deployment":"blue"}},{"metadata":null}]}`))
	})
	err := service.AddConsumers(context.Background(), "cert", certs.AddConsumersRequest{
		Consumers: []certs.AddConsumer{
			{ID: "id", Region: "region", Type: "type", Metadata: metadata},
			{ID: "without-metadata", Region: "region", Type: "type", Metadata: nil},
		},
	})
	require.NoError(t, err)
	certificate, err := service.Get(context.Background(), "cert")
	require.NoError(t, err)
	require.Len(t, certificate.Consumers, 2)
	assert.Equal(t, metadata, certificate.Consumers[0].Metadata)
	assert.Nil(t, certificate.Consumers[1].Metadata)
}

func TestUpdateConsumerMetadataErrors(t *testing.T) {
	service := versionService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"status_text":"CONFLICT"}`))
	})
	ctx := context.Background()
	require.ErrorIs(t, service.UpdateConsumerMetadata(ctx, "", "type", "region", "id", nil),
		secretsmanagererrors.ErrEmptyCertificateID)
	require.ErrorIs(t, service.UpdateConsumerMetadata(ctx, "cert", "type", "region", "id", make(chan int)),
		secretsmanagererrors.ErrCannotMarshalCertificateBody)
	require.ErrorIs(t, service.UpdateConsumerMetadata(ctx, "cert", "type", "region", "id", nil),
		secretsmanagererrors.ErrConflictStatusText)
}
