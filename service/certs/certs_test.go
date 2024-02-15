package certs_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/suite"

	"github.com/selectel/secretsmanager-go/internal/auth"
	"github.com/selectel/secretsmanager-go/internal/httpclient"
	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
	"github.com/selectel/secretsmanager-go/service/certs"
)

const (
	testDummyEndpoint = "http://example.com/"
	testDummyID       = "dummy-cert"
)

const testDummyPEMCert = `
-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIULEumDHpDEHvQ1seZB9yRX9sCgoUwDQYJKoZIhvcNAQEL
BQAwNTELMAkGA1UEBhMCUlUxEzARBgNVBAgMClNvbWUtU3RhdGUxETAPBgNVBAoM
CFNlbGVjdGVsMB4XDTI0MDEwOTA4Mzc0M1oXDTM0MDEwNjA4Mzc0M1owNTELMAkG
A1UEBhMCUlUxEzARBgNVBAgMClNvbWUtU3RhdGUxETAPBgNVBAoMCFNlbGVjdGVs
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpN0hZ9AHwKMaPUQP4Z0
4abCDxpKO2bJsdw1PxHOpkdw23dS2bH+wHWPspin5rK9i/wqg1fqKYikbukfBkdG
WjHEpgHzjHuDER0dJ4iU8kD50kg64PaUHJ1fw2QfxmH7l/DNY+9poViqwJGpGCWp
MsRw1OFQhLZKNhkNIgFugFesaBYJHdXqf7JAx+2y7AZBFniFl1PPs7Xtjn9j7m8i
2WYc+1SgU8fI4uDhH+PxjIdNrwK5bC2xg68EXI0vSkyh6Ir74Va4FWW9tlsXpw3W
d4NOorzmkDeSknbruhBHmbucmoh2oTcojziB2qRrlU8JcfjETJglZklLyzbXlk/N
WwIDAQABo1MwUTAdBgNVHQ4EFgQU8RFMuHQ+rh0RYWYEmYozljJMrjQwHwYDVR0j
BBgwFoAU8RFMuHQ+rh0RYWYEmYozljJMrjQwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEATn/WaWDnmUnYD4enM4U0HCQE6k+TodcPt3oMw+K0tfMP
AKJkD+jJvqanH6ajZNWTgEmMoiEc6bv4D4/wsiSYSIjEQDOwTkVa1wYEXeXzYc5e
GsnXXOusgR9+F5GFV8p8qDt4hozNtEycLbfN3gJURPqEJcwn7aJIVPeoWEOI5wO9
banExY6twbb91OAdW8aTkD3qicsfRpDiYHVDKqgvEJpGCTWONeUnfcKy7ni4ahov
PD3JcGkk8I+tbkM9gvxgKlXlGIHL3puskkusc5SxUSgDADLQwts5htT7TpOny7Dy
peh6PHUaY/+beb4fwNtthbs1NvtVXFUVPlxJaPFW6A==
-----END CERTIFICATE-----
`

const testDummyPEMPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuk3SFn0AfAoxo
9RA/hnThpsIPGko7Zsmx3DU/Ec6mR3Dbd1LZsf7AdY+ymKfmsr2L/CqDV+opiKRu
6R8GR0ZaMcSmAfOMe4MRHR0niJTyQPnSSDrg9pQcnV/DZB/GYfuX8M1j72mhWKrA
kakYJakyxHDU4VCEtko2GQ0iAW6AV6xoFgkd1ep/skDH7bLsBkEWeIWXU8+zte2O
f2PubyLZZhz7VKBTx8ji4OEf4/GMh02vArlsLbGDrwRcjS9KTKHoivvhVrgVZb22
WxenDdZ3g06ivOaQN5KSduu6EEeZu5yaiHahNyiPOIHapGuVTwlx+MRMmCVmSUvL
NteWT81bAgMBAAECggEAQCtITeN7BMsBhITr24XXSahrtXRy68G9CqkIU23+uSUS
aUFDjWx9WQ39a2bsdIKn5KAkmlHC61BkLLZ45mxlgjq/70tRVAaEZ1J9yG3OXfuf
OHm/VricOaZpMF+JxHh4q+FiBcVXXOzEGvOPpaYWOuh1FvLZD2cYASmVJ7ZCAV9d
AB7YXmOQtnNtbe7BKa7aPHuK7zeyflpbCmaUBLJ7GR6UYV/xjJjp5clKHP0kt0OB
E1gCveddwAVV7su/Oj1DEKI1w26fSBvmdVRf+pH4NddB1DYv2dr4scC/a2kTqZdn
U+CUwG1Zd/LtxdCHQKDn36tIXYTKuX51WZ4jq4RcJQKBgQDHtcVbF6U9RTL8M3zu
tMwyMTbbG6/2myupySYmOHzmV7XjqXCrbbMlSHQqBihE41XJo2ot8PETR6Q5mpWb
BKbAYfUZVf93cbNIj29qESqp5adlvrwW3cbyDlMa81ehk+kdkPwUvlR2fvZP7PZr
Om0eN6pFaK8ffCh6abbputwOlQKBgQDfyB4/0b8VTITkD6+DRkpbCOF0d+HJFJPr
p3K7Gf06FSL5gqTT2SXdlQufVIee/X7QMefKLS90c0JjSpzqFIkFH0GB4nOtc9jQ
sN3cEZjncWIVu1P493hBtx5Qb+oUVGBpGaDHk4hJgvUPx/t+NvNn1u/VwKHTHp5V
4h0RbJygLwKBgAEt5ptyGUyyUunAWBWExcvqFHvYvwJCylA3Wt1Q6hPmIrHUd1Db
1fn7Yow4+xXlDcWiDGd3C8VkX+jjK8z9iwqJyYu7wUVwS3G7PxouPcVBEOr95Fhy
ONGHGiCHnVXb7L169LIeqZsFhujT6mSZtLk/9OZyBs61yftnEmhw7Qm9AoGBAMzG
sD+QLP5NhjG31NEYykPhrYXJifhadz2mfguOrbWvz9Bo53HgfJD2qasETBKGP7w+
XrAYhxtVuYNorIxbfEMOpgA3+8jWgKn/nxWZmMT5cVsXj7D8q7Pe4MOUlaxCxfKG
/CSE8arrRltJke6eVEBKZC/C1ZJ+qz9F6XmfXPgLAoGAQ6MZASJ2qlYMA9xqmg/r
/rMdjYdA9PBW3X0bcAa753ZltcZeV9Afrp+Mso8W5/c4fhUJ3mMgX1vGWnWcjnLP
O8MUlX0Jx5czcb29DPSAdXjQ/pKXFyaIgjELxgb7APR0S7uQ9l7Cnm0S1Bd+ve7p
Q5g85kFYklrYDOcltZ48JPs=
-----END PRIVATE KEY-----
`

var testP12 = []byte{4, 2, 0, 6, 9}

var testCert certs.Certificate = certs.Certificate{
	Consumers: []certs.Consumer{
		{ID: "0XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region: "ru-1", Type: "octavia-listener"},
		{ID: "1XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region: "kz-228", Type: "zeliboba-enjoyer"},
	},
	DNSNames: []string{"fishing.com"},
	ID:       "9ddc1899-2a08-4bdb-9a74-4f88371d3533",
	IssuedBy: certs.IssuedBy{
		Country:       []string{"RU"},
		Locality:      []string{"string"},
		SerialNumber:  "string",
		StreetAddress: []string{"string"},
	},
	Name:       "Zeliboba",
	PrivateKey: certs.PrivateKey{Type: "RSA"},
	Serial:     "2c4ba60c7a43107bd0d6c79907dc915fdb028285",
	Validity: certs.Validity{
		BasicConstraints: true,
		NotBefore:        "2024-01-09T08:37:43Z",
		NotAfter:         "2034-01-06T08:37:43Z",
	},
	Version: 228,
}

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context.
type CertsSuite struct {
	suite.Suite
	service *certs.Service
}

// Executes before each test case
// Make sure that same HTTPClient is set in both
// service & service mock before each test.
func (suite *CertsSuite) SetupTest() {
	auth, err := auth.NewKeystoneTokenAuth("dummy")
	suite.Require().NoError(err)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	suite.service = certs.New(
		testDummyEndpoint,
		httpclient.New(auth, httpClient),
	)
	// http client, on the basis of which
	// we will perform mocks during gock initialization.
	gock.InterceptClient(httpClient)
}

// Executes after each test case.
func (suite *CertsSuite) TearDownTest() {
	// Verify that we don't have pending mocks
	suite.Require().True(gock.IsDone())
	// Flush pending mocks after test execution.
	gock.Off()

	suite.service = nil
}

// TestSuiteCerts runs all suite tests.
func TestSuiteCerts(t *testing.T) {
	suite.Run(t, new(CertsSuite))
}

func (suite *CertsSuite) TestList() {
	dummyCerts := certs.GetCertificatesResponse{
		certs.Certificate{
			Consumers: []certs.Consumer{
				{
					ID:     "0XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
					Region: "ru-1",
					Type:   "octavia-listener",
				},
				{
					ID:     "1XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
					Region: "ru-1",
					Type:   "octavia-listener",
				},
			},
			DNSNames: []string{"fishing.com"},
			ID:       "9ddc1899-2a08-4bdb-9a74-4f88371d3533",
			IssuedBy: certs.IssuedBy{
				Country:       []string{"RU"},
				Locality:      []string{"string"},
				SerialNumber:  "string",
				StreetAddress: []string{"string"},
			},
			Name:       "Zeliboba",
			PrivateKey: certs.PrivateKey{Type: "RSA"},
			Serial:     "2c4ba60c7a43107bd0d6c79907dc915fdb028285",
			Validity: certs.Validity{
				BasicConstraints: true,
				NotBefore:        "2024-01-09T08:37:43Z",
				NotAfter:         "2034-01-06T08:37:43Z",
			},
			Version: 228,
		},
	}

	gock.New(testDummyEndpoint).
		Get("/certs").
		Reply(http.StatusOK).
		File("./fixtures/certs-response-data.json")

	ctx := context.Background()
	res, err := suite.service.List(ctx)
	suite.Require().NoError(err)

	suite.Equal(dummyCerts, res)
}

func (suite *CertsSuite) TestGet() {
	tests := map[string]struct {
		certID  string
		expCert certs.Certificate
		code    int
		expErr  error
	}{
		"Valid ID": {
			testDummyID,
			testCert,
			http.StatusOK,
			nil,
		},
		"Empty ID": {
			"",
			certs.Certificate{},
			http.StatusBadRequest,
			secretsmanagererrors.ErrEmptyCertificateID,
		},
	}

	gock.New(testDummyEndpoint).
		Get(testDummyID).
		Reply(http.StatusOK).
		File("./fixtures/cert-response-data.json")

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			got, err := suite.service.Get(ctx, test.certID)

			suite.Require().ErrorIs(err, test.expErr)
			suite.Equal(test.expCert, got)
		})
	}
}

func (suite *CertsSuite) TestDelete() {
	tests := map[string]struct {
		certID string
		code   int
		expErr error
	}{
		"Valid ID": {testDummyID, http.StatusOK, nil},
		"Empty ID": {"", http.StatusBadRequest, secretsmanagererrors.ErrEmptyCertificateID},
	}

	gock.New(testDummyEndpoint).
		Delete(testDummyID).
		Reply(http.StatusOK)

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			err := suite.service.Delete(ctx, test.certID)

			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}

func (suite *CertsSuite) TestCreate() {
	tests := map[string]struct {
		req     certs.CreateCertificateRequest
		expResp certs.Certificate
		code    int
		expErr  error
	}{
		"Empty Cert Name": {
			certs.CreateCertificateRequest{
				Name: "",
				Pem:  certs.Pem{},
			},
			certs.Certificate{},
			http.StatusBadRequest,
			secretsmanagererrors.ErrEmptyCertificateName,
		},
		"Valid Cert": {
			certs.CreateCertificateRequest{
				Name: "Zeliboba",
				Pem: certs.Pem{
					Certificates: []string{testDummyPEMCert},
					PrivateKey:   testDummyPEMPrivateKey,
				},
			},
			testCert,
			http.StatusCreated,
			nil,
		},
		"Empty PEM Cert": {
			certs.CreateCertificateRequest{
				Name: "NotEmptyName",
				Pem:  certs.Pem{},
			},
			certs.Certificate{},
			http.StatusBadRequest,
			secretsmanagererrors.ErrEmptyPEMCertificate,
		},
		"Empty PEM Private Key": {
			certs.CreateCertificateRequest{
				Name: "NotEmptyName",
				Pem:  certs.Pem{Certificates: []string{testDummyPEMCert}},
			},
			certs.Certificate{},
			http.StatusBadRequest,
			secretsmanagererrors.ErrEmptyPEMPrivateKey,
		},
	}

	gock.New(testDummyEndpoint).
		Post("certs").
		Reply(http.StatusOK).
		File("./fixtures/cert-response-data.json")

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			got, err := suite.service.Create(ctx, test.req)

			suite.Require().ErrorIs(err, test.expErr)
			suite.Equal(test.expResp, got)
		})
	}
}

func (suite *CertsSuite) TestUpdateVersion() {
	tests := map[string]struct {
		certID string
		ucr    certs.UpdateCertificateVersionRequest
		code   int
		expErr error
	}{
		"Valid Update": {
			testDummyID,
			certs.UpdateCertificateVersionRequest{
				Pem: certs.Pem{
					Certificates: []string{testDummyPEMCert},
					PrivateKey:   testDummyPEMPrivateKey,
				},
			},
			http.StatusOK,
			nil,
		},
		"Empty ID": {
			"",
			certs.UpdateCertificateVersionRequest{
				Pem: certs.Pem{
					Certificates: []string{testDummyPEMCert},
					PrivateKey:   testDummyPEMPrivateKey,
				},
			},
			http.StatusBadRequest,
			secretsmanagererrors.ErrEmptyCertificateID,
		},
		"Empty Certificates": {
			testDummyID,
			certs.UpdateCertificateVersionRequest{
				Pem: certs.Pem{
					Certificates: []string{},
					PrivateKey:   testDummyPEMPrivateKey,
				},
			},
			http.StatusBadRequest,
			secretsmanagererrors.ErrEmptyPEMCertificate,
		},
		"Empty PrivateKey": {
			testDummyID,
			certs.UpdateCertificateVersionRequest{
				Pem: certs.Pem{
					Certificates: []string{testDummyPEMCert},
					PrivateKey:   "",
				},
			},
			http.StatusBadRequest,
			secretsmanagererrors.ErrEmptyPEMPrivateKey,
		},
	}

	gock.New(testDummyEndpoint).
		Post("cert/" + testDummyID) //nolint:goconst

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			err := suite.service.UpdateVersion(ctx, test.certID, test.ucr)

			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}

func (suite *CertsSuite) TestUpdateName() {
	tests := map[string]struct {
		certID string
		name   string
		code   int
		expErr error
	}{
		"Valid name": {testDummyID, "Zeliboba", http.StatusNoContent, nil},
		"Empty name": {testDummyID, "", http.StatusInternalServerError, secretsmanagererrors.ErrEmptyCertificateName},
		"Empty ID":   {"", "Zeliboba", http.StatusInternalServerError, secretsmanagererrors.ErrEmptyCertificateID},
	}

	gock.New(testDummyEndpoint).
		Put("cert/" + testDummyID).
		Reply(http.StatusOK)

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			err := suite.service.UpdateName(ctx, test.certID, test.name)

			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}

func (suite *CertsSuite) TestRemoveConsumer() {
	tests := map[string]struct {
		certID    string
		consumers certs.RemoveConsumersRequest
		code      int
		expErr    error
	}{
		"Valid New Remove": {
			testDummyID,
			certs.RemoveConsumersRequest{
				Consumers: []certs.RemoveConsumer{
					{
						ID:     "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
						Region: "ru-1",
						Type:   "zeliboba-speaker",
					},
				},
			},
			http.StatusNoContent,
			nil,
		},

		"Empty ID": {
			"",
			certs.RemoveConsumersRequest{},
			http.StatusNoContent,
			secretsmanagererrors.ErrEmptyCertificateID,
		},
	}

	gock.New(testDummyEndpoint).
		Delete("cert/" + testDummyID + "/consumers").
		Reply(http.StatusOK)

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()

			err := suite.service.RemoveConsumers(ctx, test.certID, test.consumers)
			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}

func (suite *CertsSuite) TestAddConsumer() {
	tests := map[string]struct {
		certID    string
		consumers certs.AddConsumersRequest
		code      int
		expErr    error
	}{
		"Valid New Add": {
			testDummyID,
			certs.AddConsumersRequest{
				Consumers: []certs.AddConsumer{
					{
						ID:     "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
						Region: "ru-1",
						Type:   "zeliboba-speaker",
					},
				},
			},
			http.StatusNoContent,
			nil,
		},
		"Empty ID": {
			"",
			certs.AddConsumersRequest{},
			http.StatusNoContent,
			secretsmanagererrors.ErrEmptyCertificateID,
		},
	}

	gock.New(testDummyEndpoint).
		Put("cert/(.*)/consumers").
		Reply(http.StatusOK)

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()

			err := suite.service.AddConsumers(ctx, test.certID, test.consumers)
			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}

func (suite *CertsSuite) TestGetPublicCerts() {
	gock.New(testDummyEndpoint).
		Get("cert/" + testDummyID + "/ca_chain").
		Reply(http.StatusOK).
		BodyString(testDummyPEMCert)

	ctx := context.Background()

	got, err := suite.service.GetPublicCerts(ctx, testDummyID)
	suite.Require().ErrorIs(err, nil)
	suite.Equal(testDummyPEMCert, got)
}

func (suite *CertsSuite) TestGetPrivateKey() {
	gock.New(testDummyEndpoint).
		Get("cert/" + testDummyID + "/private_key").
		Reply(http.StatusOK).
		BodyString(testDummyPEMPrivateKey)

	ctx := context.Background()

	got, err := suite.service.GetPrivateKey(ctx, testDummyID)
	suite.Require().ErrorIs(err, nil)
	suite.Equal(testDummyPEMPrivateKey, got)
}

func (suite *CertsSuite) TestGetPKCS12Bundle() {
	gock.New(testDummyEndpoint).
		Get("cert/" + testDummyID + "/p12").
		Reply(http.StatusOK).
		Body(bytes.NewReader(testP12))

	ctx := context.Background()

	got, err := suite.service.GetPKCS12Bundle(ctx, testDummyID)
	suite.Require().ErrorIs(err, nil)
	suite.Equal(testP12, got)
}
