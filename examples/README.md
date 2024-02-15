# secretsmanager-go
> [!IMPORTANT]
> Examples that cover various scenarios using secretsmanager-go.
> - [Secrets](#secrets) full flow of storing, managing and revoking secrets.
> - [Certificates](#certificates) various examples how you can manage certs.

## Client configuration
First thing to be done is set up yor client:

```go
package main

import (
	"context"

	"github.com/selectel/secretsmanager-go"
)

func main() {
	// Setting up your project KeystoneToken
	tk := "gAAAAAB..."

	// Setting Up Client
	cl, err := secretsmanager.New(
		secretsmanager.WithAuthOpts(&secretsmanager.AuthOpts{KeystoneToken: tk}),
	)
	if err != nil {
		panic(err)
	}
	
	// Prepare an empty context, for future requests.
	ctx := context.Background()
	// ...
}
```

## Secrets
> To perform any operations with secrets you have to call a `Secrets` property on client. 

### Creating a Secret
Firstly, create a secret using pre-defiend `secrets.UserSecret` data structure.
```go
mySecret := secrets.UserSecret {
    Key :   "Zeliboba"       
    Description : "Full-bodied character on Sesame Street."
    Value :  "Gigantic-oak-tree"
}
```
> [!NOTE]
> You dont have to mannualy encode `Value` into base64, sdk will do it for you.

Finally, to Upload your secret into Selectel Secrets Manager service, you have to call a `Create` method providing a context and a model from above.

```go
sc, err := cl.Secrets.Create(ctx, mySecret)
// ...
```

Expanded flow with secrets can be found in[📄 main.go](./create-list-update-delete-secrets/main.go)

## Certificates
> To perform any operations with certificates you have to call a `Certificates` property on client. 

### Creating a Certificates
Firstly, create a secret using pre-defiend `certs.CreateCertificateRequest` data structure.

```go
cert := `
-----BEGIN CERTIFICATE-----
...
`

pk := `
-----BEGIN PRIVATE KEY-----
...
`

myCert := certs.CreateCertificateRequest{
	Name: "Rust-Programming-Language",
	Pem: certs.Pem{
		Certificates: []string{cert},
		PrivateKey: pk,
	},
}
```

Finally, to Upload your certificate into Selectel Secrets Manager service, you have to call a `Create` method providing a context and a model from above.

```go
createdCrt, errCR := cl.Certificates.Create(ctx, myCert)
// ...
```
As a result, you've got a response with SDK's model certificate, that has been just created and stored in Secrets Manager service:
```go 
// createdCrt
{
	Consumers:[] 
	DNSNames:[] 
	ID:9d0206bb-3a4c-42f7-a2dc-487b255e7a5c 
	IssuedBy:{
		Country:[RU] 
		Locality:[] 
		SerialNumber: 
		StreetAddress:[]
	} 
	Name:Rust-Programming 
	PrivateKey:{Type:RSA} 
	Serial:2c4ba60c7a43107bd0d6c79907dc915fdb028285 
	Validity:{
		BasicConstraints:true 
		NotAfter:2034-01-06T08:37:43Z 
		NotBefore:2024-01-09T08:37:43Z
	} 
	Version:1
}
```

Expanded flow with certificates can be found in[📄 main.go](./create-addconsumers-update-get-certs/main.go)
