package certs

// Certificate entity received by the user when making a request
// GET /cert/{id}.
type Certificate struct {
	Consumers  []Consumer `json:"consumers"`
	DNSNames   []string   `json:"dns_names"`
	ID         string     `json:"id"`
	IssuedBy   IssuedBy   `json:"issued_by"`
	Name       string     `json:"name"`
	PrivateKey PrivateKey `json:"private_key"`
	Serial     string     `json:"serial"`
	Validity   Validity   `json:"validity"`
	Version    int64      `json:"version"`
}

type Consumer struct {
	ID     string `json:"id"`
	Region string `json:"region"`
	Type   string `json:"type"`
}

type IssuedBy struct {
	Country       []string `json:"country"`
	Locality      []string `json:"locality"`
	SerialNumber  string   `json:"serialNumber"`  //nolint:tagliatelle
	StreetAddress []string `json:"streetAddress"` //nolint:tagliatelle
}

type PrivateKey struct {
	Type string `json:"type"`
}

type Validity struct {
	BasicConstraints bool   `json:"basic_constraints"`
	NotAfter         string `json:"notAfter"`  //nolint:tagliatelle
	NotBefore        string `json:"notBefore"` //nolint:tagliatelle
}

// UpdateCertificateVersionRequest entity send by the user when making a request
// POST /cert/{id}.
type UpdateCertificateVersionRequest struct {
	Pem Pem `json:"pem"`
}

type Pem struct {
	Certificates []string `json:"certificates"`
	PrivateKey   string   `json:"private_key"`
}

// UpdateCertificateNameRequest entity send by the user when making a request
// PUT /cert/{id}.
type UpdateCertificateNameRequest struct {
	Name string `json:"name"`
}

// RemoveConsumerRequest entity send by the user when making a request
// DELETE /cert/{id}/consumers.
type RemoveConsumersRequest struct {
	Consumers []RemoveConsumer `json:"consumers,omitempty"`
}

type RemoveConsumer struct {
	ID     string `json:"id"`
	Region string `json:"region"`
	Type   string `json:"type"`
}

// AddConsumersRequest entity send by the user when making a request
// PUT /cert/{id}/consumers.
type AddConsumersRequest struct {
	Consumers []AddConsumer `json:"consumers,omitempty"`
}

type AddConsumer struct {
	ID     string `json:"id"`
	Region string `json:"region"`
	Type   string `json:"type"`
}

// GetCertificatesResponse entity received by the user when making a request
// GET /certs.
type GetCertificatesResponse []Certificate

// CreateCertificateRequest entity received by the user when making a request
// POST /certs.
type CreateCertificateRequest struct {
	Name string `json:"name"`
	Pem  Pem    `json:"pem"`
}
