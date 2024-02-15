# secretsmanager-go: Go SDK for Secrets Manager API
[![Go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/selectel/secretsmanager-go/)
[![Go Report Card](https://goreportcard.com/badge/github.com/selectel/secretsmanager-go)](https://goreportcard.com/report/github.com/selectel/secretsmanager-go/)
[![codecov](https://codecov.io/gh/selectel/secretsmanager-go/branch/main/graph/badge.svg)](https://codecov.io/gh/selectel/secretsmanager-go)


> [!NOTE]
> Secrets Manager SDK implements the Secrets Manager API facilitating the tasks of storing, managing and revoking secrets/certificates.

## Documentation
> [!IMPORTANT]
> The Go library documentation is available at [go.dev](https://pkg.go.dev/github.com/selectel/secretsmanager-go/).

## Getting started
### Install
```sh
go get github.com/selectel/secretsmanager-go
```

## Authentication

To work with Selectel API:
- You're gonna need a Selectel account.
- [Keystone Token](https://developers.selectel.com/docs/control-panel/authorization/#keystone-token)   

## Usage
> [!IMPORTANT]
> At the moment you need to pass a **Valid** Keystone Token to use it.

```go
package main

import (
	"context"
	"log"
	"fmt"

	"github.com/selectel/secretsmanager-go"
)

// Setting Up your project KeystoneToken
const KeystoneToken = "gAAAAAB..."

func main() {
	// Setting Up Client
	cl, err := secretsmanager.New(
		secretsmanager.WithAuthOpts(&secretsmanager.AuthOpts{KeystoneToken: KeystoneToken}),
	)
	if err != nil {
		log.Fatal(err)
	}
	
	// Prepare an empty context, for future requests.
	ctx := context.Background()

	sc, err := cl.Secrets.List(ctx)
	if err != nil {
		    log.Fatal(err)
	}
	fmt.Printf("Retrived secrets: %+v\n", sc)
	// ...
}
```

## Additional info
> [!NOTE]
>
> More examples available in [📁 examples](./examples) section.
>
> For advanced topics and guides [📁 docs](./docs) section.