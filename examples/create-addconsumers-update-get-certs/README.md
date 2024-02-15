# Certificates Usage

When working with certificates, you have to import the folowing modules:
```go
package main

import (
    "github.com/selectel/secretsmanager-go"
    "github.com/selectel/secretsmanager-go/service/certs"
)
```

> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
>
> <details>
>  <summary>Basic Flow with Certificate in Secrets Manаger</summary>
>
>    ```go
>    createdCrt, _ := cl.Certificates.Create(ctx, myCertificate)
>    /*
>    {
>        Consumers:[],
>        DNSNames:[],
>        ID:9d0206bb-3a4c-42f7-a2dc-487b255e7a5c,
>        IssuedBy:{
>            Country:[RU],
>            Locality:[], 
>            SerialNumber: ,
>            StreetAddress:[],
>        }, 
>        Name:Rust-Programming, 
>        PrivateKey:{Type:RSA}, 
>        Serial:2c4ba60c7a43107bd0d6c79907dc915fdb028285, 
>        Validity:{
>            BasicConstraints:true, 
>            NotAfter:2034-01-06T08:37:43Z,
>            NotBefore:2024-01-09T08:37:43Z,
>        },
>        Version:1,
>   }
>   */
>
>   // We can get it from Secrets Manаger, by calling Get method
>   gotCrt, _ := cl.Certificates.Get(ctx, createdCrt.ID)
>   
>   // To Delete it, simply call Delete method
>   err := cl.Certificates.Delete(ctx, createdCrt.ID)
>
>   // Now we can check that ther's no Certificates in Secrets Manаger by List method, that shows all Certificates in project
>   certs, err := cl.Certificates.List(ctx)
>   ```
> </details>


> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
>
> <details>
>  <summary>Adding/Deleting consumers into/from recently created certificate</summary>
>
>    ```go 
>	consumers := certs.AddConsumersRequest{
>		Consumers: []certs.AddConsumer{
>			{ID: "01XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region: "ru-1", Type: "octavia-listener"},
>			{ID: "01XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region: "kz-4", Type: "octavia-listener"},
>		},
>	}
>   
>    _ = cl.Certificates.AddConsumers(ctx, crtID, consumers)
>    gotCrt, _ := cl.Certificates.Get(ctx, crtID)
>    gotCrt{
>       Consumers:[
>            {ID:"01XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region:"ru-1", Type:"octavia-listener"},
>            {ID:"01XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", Region:"kz-4", Type:"octavia-listener"}
>        ],
>        DNSNames:[],
>        ...
>    }
>    
>    // If you wish to Delete consumers from the certificate
>    _ = cl.Certificates.RemoveConsumers(ctx, crtID, consumers)
>    ```
> </details>



> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
>
> <details>
>  <summary>Updating Certificates' Name</summary>
>
>    ```go
>	err := cl.Certificates.UpdateName(ctx, crtID,  "Rust-Programming-Language")
>    if err != nil {
>		log.Fatal(err)
>	 }
>    gotCrt, _ := cl.Certificates.Get(ctx, crtID)
>    fmt.Println(gotCrt.Name)
>    // > "Rust-Programming-Language"
>    ```
> </details>

> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
>
> <details>
>  <summary>Updating Certificate' Version</summary>
>
>    Consider you wish to Update Certificate without Creating New One, for example add fresher certs
>   ```go
>   // Fill Update Structure
>   updVersion := certs.UpdateCertificateVersionRequest{
>		Pem: certs.Pem{
>			Certificates: []string{DummyCert},
>			PrivateKey:   DummyPrivateKey,
>		},
>	}
>   
>   // Make an UpdateVersion Request
>   err := cl.Certificates.UpdateVersion(ctx, crtID, updVersion)
>	if err != nil {
>		log.Fatal(err)
>	}
>   
>   // Check result
>   gotCrt, _ := cl.Certificates.Get(ctx, crtID)
>   fmt.Println(gotCrt.Version)
>   // > 2
>   ```
> </details>


> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
>
> <details>
>  <summary>Get Certificate' CA Chain / PK / PKCS12</summary>
>
>    
>   ```go
> 	// Get a public certs for certificate.
> 	gotPubCrt, _ := cl.Certificates.GetPublicCerts(ctx, crtID)
> 	fmt.Printf("%+v\n", gotPubCrt)
> 	/*
> 		-----BEGIN CERTIFICATE-----
> 		...
> 		-----END CERTIFICATE-----
> 	*/
> 
> 	// Get a private key for certificate.
> 	gotPK, _ := cl.Certificates.GetPrivateKey(ctx, crtID)
> 	fmt.Printf("%+v\n", gotPK)
> 	/*
> 		-----BEGIN PRIVATE KEY-----
> 		...
> 		-----END PRIVATE KEY-----
> 	*/
> 
> 	// Get a everything related to this certificate in PKCS#12  bundle.
> 	gotPKCS12, _ := cl.Certificates.GetPKCS12Bundle(ctx, crtID)
> 	fmt.Printf("%+v\n", gotPKCS12)
> 	// [48 130 9 131 2 1 3 48 130 9 79 6 9 42 134 ....
>   ```
> </details>