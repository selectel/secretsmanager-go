package secretsmanagererrors

import (
	"errors"
	"fmt"
)

const (
	// X-Auth-Token error code.
	AuthErrorCode = "X-Auth-Token is unauthorized"
)

var (
	// Errors for Auth.
	ErrClientNoAuthOpts     = errors.New("CLIENT_NO_AUTH_METHOD")
	ErrAuthTokenUnathorized = errors.New("AUTH_TOKEN_UNAUTHORIZED")

	// Errors for Secrets Service.
	ErrEmptySecretName         = errors.New("EMPTY_SECRET_NAME")
	ErrEmptySecretValue        = errors.New("EMPTY_SECRET_DESC")
	ErrCannotMarshalSecretBody = errors.New("CANNOT_MARSHAL_SECRET")

	// Errors for Certificates Service.
	ErrEmptyCertificateID           = errors.New("EMPTY_CERT_ID")
	ErrEmptyCertificateName         = errors.New("EMPTY_CERT_NAME")
	ErrEmptyPEMCertificate          = errors.New("EMPTY_CERT_PEM_CERT")
	ErrEmptyPEMPrivateKey           = errors.New("EMPTY_CERT_PEM_PK")
	ErrCannotMarshalCertificateBody = errors.New("CANNOT_MARSHAL_CERT")

	// SDK Common Errors.
	ErrInternalAppError     = errors.New("INTERNAL_APP_ERROR")
	ErrCannotDoRequest      = errors.New("CANNOT_DO_REQUEST")
	ErrCannotFormatEndpoint = errors.New("CANNOT_FORMAT_ENDPOINT")
	ErrCannotReadBody       = errors.New("CANNOT_READ_RESPONSE_BODY")
	ErrCannotUnmarshalBody  = errors.New("CANNOT_UNMARSHAL_JSON")

	// Errors from Backend.
	ErrBadRequestStatusText    = errors.New("INCORRECT_REQUEST")
	ErrInternalErrorStatusText = errors.New("INTERNAL_SERVER_ERROR")
	ErrUnauthorizedStatusText  = errors.New("UNAUTHORIZED")
	ErrForbiddenStatusText     = errors.New("FORBIDDEN")
	ErrOverQuotasStatusText    = errors.New("OVER_QUOTAS")
	ErrNotFoundStatusText      = errors.New("NOT_FOUND")
	ErrConflictStatusText      = errors.New("CONFLICT")
	ErrTooManyRequestsText     = errors.New("TOO_MANY_REQUESTS")
	ErrMethodNotAllowed        = errors.New("NOT_ALLOWED")

	ErrUnknown = errors.New("UNKNOWN_ERROR")

	//nolint:gochecknoglobals
	stringToError = map[string]error{
		ErrClientNoAuthOpts.Error():     ErrClientNoAuthOpts,
		ErrAuthTokenUnathorized.Error(): ErrAuthTokenUnathorized,

		ErrEmptySecretName.Error():         ErrEmptySecretName,
		ErrEmptySecretValue.Error():        ErrEmptySecretValue,
		ErrCannotMarshalSecretBody.Error(): ErrCannotMarshalSecretBody,

		ErrEmptyCertificateID.Error():           ErrEmptyCertificateID,
		ErrEmptyCertificateName.Error():         ErrEmptyCertificateName,
		ErrEmptyPEMCertificate.Error():          ErrEmptyPEMCertificate,
		ErrEmptyPEMPrivateKey.Error():           ErrEmptyPEMPrivateKey,
		ErrCannotMarshalCertificateBody.Error(): ErrCannotMarshalCertificateBody,

		ErrInternalAppError.Error():     ErrInternalAppError,
		ErrCannotDoRequest.Error():      ErrCannotDoRequest,
		ErrCannotFormatEndpoint.Error(): ErrCannotFormatEndpoint,
		ErrCannotReadBody.Error():       ErrCannotReadBody,
		ErrCannotUnmarshalBody.Error():  ErrCannotUnmarshalBody,

		ErrBadRequestStatusText.Error():    ErrBadRequestStatusText,
		ErrInternalErrorStatusText.Error(): ErrInternalErrorStatusText,
		ErrUnauthorizedStatusText.Error():  ErrInternalErrorStatusText,
		ErrForbiddenStatusText.Error():     ErrForbiddenStatusText,
		ErrOverQuotasStatusText.Error():    ErrOverQuotasStatusText,
		ErrNotFoundStatusText.Error():      ErrNotFoundStatusText,
		ErrConflictStatusText.Error():      ErrConflictStatusText,
		ErrTooManyRequestsText.Error():     ErrTooManyRequestsText,
		ErrMethodNotAllowed.Error():        ErrMethodNotAllowed,

		ErrUnknown.Error(): ErrUnknown,
	}
)

// ErrResponse — represents error returned from Backend responsible
// for Secrets & Certs services.
type ErrResponse struct {
	HTTPStatusCode int    `json:"-"`
	ErrorText      string `json:"error_text,omitempty"`
	StatusText     string `json:"status_text"`
}

func GetError(errorString string) error {
	err, ok := stringToError[errorString]
	if !ok {
		return nil
	}
	return err
}

// Error — an error returned by the Secrets Manager SDK to user.
type Error struct {
	Err  error
	Desc string
}

func (e Error) Error() string {
	return fmt.Sprintf("secretsmanager-go: error — %s: %s", e.Err.Error(), e.Desc)
}

func (e Error) Is(err error) bool {
	return errors.Is(e.Err, err)
}
