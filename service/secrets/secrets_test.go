package secrets_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/suite"

	"github.com/selectel/secretsmanager-go/internal/auth"
	"github.com/selectel/secretsmanager-go/internal/httpclient"
	"github.com/selectel/secretsmanager-go/secretsmanagererrors"
	"github.com/selectel/secretsmanager-go/service/secrets"
)

const (
	testDummyEndpoint = "http://example.com/"
	testDummyKey      = "dummy-secret"
)

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context.
type SecretsSuite struct {
	suite.Suite
	service *secrets.Service
}

// Executes before each test case
// Make sure that same HTTPClient is set in both
// service & service mock before each test.
func (suite *SecretsSuite) SetupTest() {
	auth, err := auth.NewKeystoneTokenAuth("dummy")
	suite.Require().NoError(err)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	suite.service = secrets.New(
		testDummyEndpoint,
		httpclient.New(auth, httpClient),
	)
	// http client, on the basis of which
	// we will perform mocks during gock initialization.
	gock.InterceptClient(httpClient)
}

// Executes after each test case.
func (suite *SecretsSuite) TearDownTest() {
	// Verify that we don't have pending mocks
	suite.Require().True(gock.IsDone())
	// Flush pending mocks after test execution.
	gock.Off()

	suite.service = nil
}

// TestSuiteSecrets runs all suite tests.
func TestSuiteSecrets(t *testing.T) {
	suite.Run(t, new(SecretsSuite))
}

func (suite *SecretsSuite) TestList() {
	expectedSecrets := secrets.Secrets{
		Keys: []secrets.Key{
			{
				Metadata: secrets.SecretMetadata{
					CreatedAt:   "2023-12-26T09:48:01Z",
					Description: "Bla",
				},
				Name: "Bla",
				Type: "Secret",
			},
			{
				Metadata: secrets.SecretMetadata{
					CreatedAt:   "2007-12-26T09:48:01Z",
					Description: "IAM",
				},
				Name: "IAM",
				Type: "Secret",
			},
		},
	}

	gock.New(testDummyEndpoint+"?").
		Get("").
		MatchParam("list", "").
		Reply(http.StatusOK).
		File("./fixtures/secrets-response-data.json")

	ctx := context.Background()
	res, err := suite.service.List(ctx)
	suite.Require().NoError(err)

	suite.Equal(expectedSecrets, res)
}

func (suite *SecretsSuite) TestDelete() {
	tests := map[string]struct {
		key    string
		code   int
		expErr error
	}{
		"Successful deletion": {testDummyKey, http.StatusNoContent, nil},
		"Empty secret":        {"", http.StatusBadRequest, secretsmanagererrors.ErrEmptySecretName},
	}

	gock.New(testDummyEndpoint).
		Delete(testDummyKey).
		Reply(http.StatusOK)

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			err := suite.service.Delete(ctx, test.key)

			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}

func (suite *SecretsSuite) TestGet() {
	tests := map[string]struct {
		key       string
		expSecret secrets.Secret
		code      int
		expErr    error
	}{
		"Successful Get": {
			testDummyKey,
			secrets.Secret{
				Description: "dummy-description",
				Name:        testDummyKey,
				Version: secrets.SecretVersion{
					CreatedAt: "2023-12-26T09:48:01Z",
					Value:     "dmFsdWU=",
					VersionID: 0,
				},
			},
			http.StatusOK,
			nil,
		},
		"Empty Key": {
			"",
			secrets.Secret{},
			http.StatusInternalServerError,
			secretsmanagererrors.ErrEmptySecretName,
		},
	}

	gock.New(testDummyEndpoint).
		Get(testDummyKey).
		Reply(http.StatusOK).
		File("./fixtures/secret-response-data.json")

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			got, err := suite.service.Get(ctx, test.key)

			suite.Require().ErrorIs(err, test.expErr)
			suite.Equal(test.expSecret, got)
		})
	}
}

func (suite *SecretsSuite) TestUpdate() {
	tests := map[string]struct {
		key       string
		expSecret secrets.UserSecret
		code      int
		expErr    error
	}{
		"Successful Update": {
			testDummyKey,
			secrets.UserSecret{
				Key:         testDummyKey,
				Description: "dummy-description",
			},
			http.StatusOK,
			nil,
		},
		"Empty Description": {
			testDummyKey,
			secrets.UserSecret{
				Key: testDummyKey,
			},
			http.StatusOK,
			nil,
		},
		"Empty Key": {
			"",
			secrets.UserSecret{
				Key:         "",
				Description: "dummy-description",
			},
			http.StatusInternalServerError,
			secretsmanagererrors.ErrEmptySecretName,
		},
	}

	gock.New(testDummyEndpoint).
		Put(testDummyKey).
		Reply(http.StatusOK)

	gock.New(testDummyEndpoint).
		Put("").
		Reply(http.StatusOK)

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			err := suite.service.Update(ctx, test.expSecret)

			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}

func (suite *SecretsSuite) TestCreate() {
	tests := map[string]struct {
		key       string
		expSecret secrets.UserSecret
		code      int
		expErr    error
	}{
		"Successful Create": {
			testDummyKey,
			secrets.UserSecret{
				Key:         testDummyKey,
				Description: "dummy-description",
				Value:       "dmFsdWU=",
			},
			http.StatusOK,
			nil,
		},
		"Empty Description": {
			testDummyKey,
			secrets.UserSecret{
				Key:   testDummyKey,
				Value: "dmFsdWU=",
			},
			http.StatusOK,
			nil,
		},
		"Empty Name": {
			"",
			secrets.UserSecret{
				Key:   "",
				Value: "dmFsdWU=",
			},
			http.StatusInternalServerError,
			secretsmanagererrors.ErrEmptySecretName,
		},
		"Empty Value": {
			testDummyKey,
			secrets.UserSecret{
				Key:   testDummyKey,
				Value: "",
			},
			http.StatusInternalServerError,
			secretsmanagererrors.ErrEmptySecretValue,
		},
	}

	gock.New(testDummyEndpoint).
		Post(testDummyKey).
		Reply(http.StatusOK)

	gock.New(testDummyEndpoint).
		Post("").
		Reply(http.StatusOK)

	for name, test := range tests {
		suite.T().Run(name, func(t *testing.T) {
			ctx := context.Background()
			err := suite.service.Create(ctx, test.expSecret)

			suite.Require().ErrorIs(err, test.expErr)
		})
	}
}
