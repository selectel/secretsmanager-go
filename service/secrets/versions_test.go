package secrets_test

import (
	"context"
	"encoding/base64"
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
	"github.com/selectel/secretsmanager-go/service/secrets"
)

func versionService(t *testing.T, handler http.HandlerFunc) *secrets.Service {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	authenticator, err := auth.NewKeystoneTokenAuth("dummy")
	require.NoError(t, err)
	return secrets.New(server.URL, httpclient.New(authenticator, server.Client()))
}

func TestCreateSecretVersion(t *testing.T) {
	for _, key := range []struct {
		name string
		path string
	}{
		{name: "database-password", path: "/v1/database-password/versions"},
		{name: "key/%?#", path: "/v1/key%2F%25%3F%23/versions"},
	} {
		for _, activate := range []bool{false, true} {
			t.Run(key.name+"/"+strconv.FormatBool(activate), func(t *testing.T) {
				value := "plain\x00value/пароль"
				encoded := base64.StdEncoding.EncodeToString([]byte(value))
				service := versionService(t, func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, http.MethodPost, r.Method)
					assert.Equal(t, key.path, r.URL.EscapedPath())
					assert.Equal(t, strconv.FormatBool(activate), r.URL.Query().Get("activate"))
					var payload map[string]string
					require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
					assert.Equal(t, map[string]string{"value": encoded}, payload)
					require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
						"version_id": 42, "value": encoded, "is_current": activate,
						"created_at": "2026-11-13T10:00:00Z",
					}))
				})
				result, err := service.CreateVersion(context.Background(), key.name, value, activate)
				require.NoError(t, err)
				assert.Equal(t, uint(42), result.VersionID)
				assert.Equal(t, encoded, result.Value)
				assert.Equal(t, activate, result.IsCurrent)
				assert.Equal(t, "2026-11-13T10:00:00Z", result.CreatedAt)
			})
		}
	}
}

func TestSecretVersionRoutes(t *testing.T) {
	service := versionService(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/key/versions":
			assert.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write([]byte(`{"name":"key","description":"description","created_at":"2026-11-12T10:00:00Z",` +
				`"versions":[{"version_id":42,"created_at":"2026-11-13T10:00:00Z","is_current":true}]}`))
		case "/v1/key/versions/42":
			assert.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write([]byte(`{"version_id":42,"value":"dmFsdWU=","is_current":false}`))
		case "/v1/key/versions/18446744073709551615/activate":
			assert.Equal(t, http.MethodPost, r.Method)
			_, _ = w.Write([]byte(`{"version_id":18446744073709551615,` +
				`"created_at":"2026-11-13T10:00:00Z","is_current":true}`))
		default:
			t.Errorf("unexpected route: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	versions, err := service.ListVersions(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, "key", versions.Name)
	assert.Equal(t, "description", versions.Description)
	assert.Equal(t, "2026-11-12T10:00:00Z", versions.CreatedAt)
	require.Len(t, versions.Versions, 1)
	assert.Equal(t, secrets.VersionMetadata{
		VersionID: 42, CreatedAt: "2026-11-13T10:00:00Z", IsCurrent: true,
	}, versions.Versions[0])
	version, err := service.GetVersion(ctx, "key", 42)
	require.NoError(t, err)
	assert.Equal(t, uint(42), version.VersionID)
	assert.Equal(t, "dmFsdWU=", version.Value)
	assert.False(t, version.IsCurrent)
	active, err := service.ActivateVersion(ctx, "key", ^uint64(0))
	require.NoError(t, err)
	assert.Equal(t, ^uint64(0), active.VersionID)
	assert.True(t, active.IsCurrent)
	assert.Equal(t, "2026-11-13T10:00:00Z", active.CreatedAt)
}

func TestSecretVersionErrors(t *testing.T) {
	calls := map[string]func(*secrets.Service, string, uint64) error{
		"create": func(s *secrets.Service, key string, _ uint64) error {
			_, err := s.CreateVersion(context.Background(), key, "value", false)
			if err != nil {
				return fmt.Errorf("create secret version: %w", err)
			}
			return nil
		},
		"list": func(s *secrets.Service, key string, _ uint64) error {
			_, err := s.ListVersions(context.Background(), key)
			if err != nil {
				return fmt.Errorf("list secret versions: %w", err)
			}
			return nil
		},
		"get": func(s *secrets.Service, key string, version uint64) error {
			_, err := s.GetVersion(context.Background(), key, version)
			if err != nil {
				return fmt.Errorf("get secret version: %w", err)
			}
			return nil
		},
		"activate": func(s *secrets.Service, key string, version uint64) error {
			_, err := s.ActivateVersion(context.Background(), key, version)
			if err != nil {
				return fmt.Errorf("activate secret version: %w", err)
			}
			return nil
		},
	}
	service := versionService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status_text":"NOT_FOUND","error_text":"missing version"}`))
	})
	malformed := versionService(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("invalid JSON"))
	})
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call(service, "", 42), secretsmanagererrors.ErrEmptySecretName)
			require.ErrorIs(t, call(service, "key", 42), secretsmanagererrors.ErrNotFoundStatusText)
			require.ErrorIs(t, call(malformed, "key", 42), secretsmanagererrors.ErrCannotUnmarshalBody)
			if name == "get" || name == "activate" {
				require.ErrorIs(t, call(service, "key", 0), secretsmanagererrors.ErrBadRequestStatusText)
			}
		})
	}
	_, err := service.CreateVersion(context.Background(), "key", "", true)
	require.ErrorIs(t, err, secretsmanagererrors.ErrEmptySecretValue)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = service.GetVersion(ctx, "key", 42)
	require.ErrorIs(t, err, secretsmanagererrors.ErrInternalAppError)
}
