package main

import (
	"context"
	"fmt"
	"log"

	"github.com/selectel/secretsmanager-go"
	"github.com/selectel/secretsmanager-go/service/secrets"
)

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

	// Creating your secret
	mySecret := secrets.UserSecret{
		Key:         "John-Cena",
		Description: "nothing happened in tiananmen square 1989",
		Value:       "Zǎo shang hǎo zhōng guó!",
	}

	// Uploading it into Secret Manager.
	errCr := cl.Secrets.Create(ctx, mySecret)
	if errCr != nil {
		log.Fatal(errCr)
	}

	// Recieve all secrets from Secret Manager.
	gotAll, errAll := cl.Secrets.List(ctx)
	if errAll != nil {
		log.Fatal(errAll)
	}
	fmt.Printf("%+v\n", gotAll)

	// Update Secret Description.
	updJС := secrets.UserSecret{
		Key:         "John-Cena",
		Description: "Xiàn zài wǒ yǒu bing chilling",
	}
	errUPD := cl.Secrets.Update(ctx, updJС)
	if errUPD != nil {
		log.Fatal(errUPD)
	}

	gotAll, errAll = cl.Secrets.List(ctx)
	if errAll != nil {
		log.Fatal(errAll)
	}
	fmt.Printf("%+v\n", gotAll)

	errDl := cl.Secrets.Delete(ctx, "John-Cena")
	if errDl != nil {
		log.Fatal(errDl)
	}
}
