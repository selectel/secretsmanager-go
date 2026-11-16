package certs

import (
	"context"
	"net/http"
	"net/url"
)

// UpdateConsumerMetadata replaces consumer metadata. Nil explicitly clears it.
func (s Service) UpdateConsumerMetadata(
	ctx context.Context, id, consumerType, consumerRegion, consumerID string, metadata any,
) error {
	endpoint, err := s.certificateEndpoint(
		id, "consumers", url.PathEscape(consumerType), url.PathEscape(consumerRegion), url.PathEscape(consumerID),
	)
	if err != nil {
		return err
	}
	request := struct {
		Metadata any `json:"metadata"`
	}{Metadata: metadata}
	return s.certificateRequest(ctx, http.MethodPatch, endpoint, request, nil)
}
