package secrets

// Secrets — entity received by the user when making a request
// GET /.
type Secrets struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Metadata SecretMetadata `json:"metadata"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
}

type SecretMetadata struct {
	CreatedAt   string `json:"created_at"`
	Description string `json:"description"`
}

// Secret — entity received by the user when making a request
// GET /{key}.
type Secret struct {
	Description string        `json:"description,omitempty"`
	Name        string        `json:"name"`
	Version     SecretVersion `json:"version"`
}

type SecretVersion struct {
	CreatedAt string `json:"created_at"`
	IsCurrent bool   `json:"is_current"`
	Value     string `json:"value"` // The value of the secret in base64.
	VersionID uint   `json:"version_id"`
}

// VersionMetadata describes a secret version without its value.
type VersionMetadata struct {
	VersionID uint64 `json:"version_id"`
	CreatedAt string `json:"created_at"`
	IsCurrent bool   `json:"is_current"`
}

// SecretVersions aggregates metadata about a secret and its versions.
type SecretVersions struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Versions    []VersionMetadata `json:"versions"`
	CreatedAt   string            `json:"created_at,omitempty"`
}

// UserSecret — an entity created by the user to save it in the Secret Manager
// POST /{key} and PUT /{key}.
type UserSecret struct {
	Key         string `json:"-"`
	Description string `json:"description,omitempty"`
	Value       string `json:"value"` // The value of the secret in base64.
}
