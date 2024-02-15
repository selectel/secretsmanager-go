package auth

import "github.com/selectel/secretsmanager-go/secretsmanagererrors"

// Type — provides a general behaviour for all availbale Auth types;
// it is a bridge from AuthOpts, provided by user
// for retrieving KeystoneToken from GetKeystoneToken().
// for example if we consider to add BasicAuth (login, pass)
// it should have a realization of GetKeystoneToken().
type Type interface {
	GetKeystoneToken() string
}

func NewKeystoneTokenAuth(kst string) (Type, error) {
	if len(kst) == 0 {
		return nil, secretsmanagererrors.Error{
			Err:  secretsmanagererrors.ErrClientNoAuthOpts,
			Desc: "provided KeystoneToken is empty",
		}
	}

	return &keystoneTokenAuth{kst: kst}, nil
}

// KeystoneTokenAuth represents Keystone token authentication method.
// It conforms to Type interface.
type keystoneTokenAuth struct {
	kst string
}

func (ksa *keystoneTokenAuth) GetKeystoneToken() string {
	return ksa.kst
}
