package main

import (
	"context"
	"fmt"
	"log"

	"github.com/selectel/secretsmanager-go"
	"github.com/selectel/secretsmanager-go/service/certs"
)

// DummyCert is a cert in PEM format.
const DummyCert = `
-----BEGIN CERTIFICATE-----
peh6PHUaY/+beb4fwNtthbs1NvtVXFUVPlxJaPFW6A==
-----END CERTIFICATE-----
`

// DummyPrivateKey is a private key for cert above in PEM format.
const DummyPrivateKey = `
-----BEGIN PRIVATE KEY-----
Q5g85kFYklrYDOcltZ48JPs=
-----END PRIVATE KEY-----
`

func main() {
	// Setting up your project KeystoneToken.
	tk := "gAAAAAB..."

	// Setting Up Client.
	cl, err := secretsmanager.New(
		secretsmanager.WithAuthOpts(&secretsmanager.AuthOpts{KeystoneToken: tk}),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Prepare an empty context, for future requests.
	ctx := context.Background()

	// Building your certificate.
	stepikCert := certs.CreateCertificateRequest{
		Name: "Rust-Programming",
		Pem: certs.Pem{
			Certificates: []string{DummyCert},
			PrivateKey:   DummyPrivateKey,
		},
	}

	// Uploading it into Secret Manager.
	createdCrt, errCR := cl.Certificates.Create(ctx, stepikCert)
	if err != nil {
		log.Fatal(errCR)
	}
	fmt.Printf("SC: %+v\n", createdCrt)

	// Store ID we, we also could use ID field from createdCrt createdCrt.ID.
	crtID := "9d0206bb-3a4c-42f7-a2dc-487b255e7a5c"

	// Adding consumers into recently created certificate.
	consumers := certs.AddConsumersRequest{
		Consumers: []certs.AddConsumer{
			{ID: "01XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region: "ru-1", Type: "octavia-listener"},
			{ID: "01XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region: "kz-4", Type: "octavia-listener"},
		},
	}

	// Making a request for add them.
	errCons := cl.Certificates.AddConsumers(ctx, crtID, consumers)
	if errCons != nil {
		log.Fatal(errCons)
	}

	// Check the results by getting updated certificate by its ID.
	gotCrt, errGet := cl.Certificates.Get(ctx, crtID)
	if errGet != nil {
		log.Fatal(errGet)
	}
	fmt.Printf("SC: %+v\n", gotCrt)

	// If we want to change cert name we can do the same.
	errUN := cl.Certificates.UpdateName(ctx, crtID, "Rust-Programming-Language")
	if errUN != nil {
		log.Fatal(errUN)
	}

	gotCrt, _ = cl.Certificates.Get(ctx, crtID)
	fmt.Printf("%+v\n", gotCrt)

	// In case we want to update certVersion, for example add fresher certs:
	updVer := certs.UpdateCertificateVersionRequest{
		Pem: certs.Pem{
			Certificates: []string{DummyCert},
			PrivateKey:   DummyPrivateKey,
		},
	}

	errUV := cl.Certificates.UpdateVersion(ctx, crtID, updVer)
	if errUV != nil {
		log.Fatal(errUV)
	}

	// As a result you see the same crt with
	// Rust-Programming-Language name and same ID however its Version is now 2.
	gotCrt, _ = cl.Certificates.Get(ctx, crtID)
	fmt.Printf("%+v\n", gotCrt.Version)

	// Get a public certs for certificate.
	gotPubCrt, _ := cl.Certificates.GetPublicCerts(ctx, crtID)
	fmt.Printf("%+v\n", gotPubCrt)

	// Get a private key for certificate.
	gotPK, _ := cl.Certificates.GetPrivateKey(ctx, crtID)
	fmt.Printf("%+v\n", gotPK)

	// Get a everything related to this certificate in PKCS#12 bundle.
	gotPKCS12, _ := cl.Certificates.GetPKCS12Bundle(ctx, crtID)
	fmt.Printf("%+v\n", gotPKCS12)
}
