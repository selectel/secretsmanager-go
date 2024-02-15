# Secrets Usage

When working with secrets, you have to import the folowing modules:
```go
package main

import (
    "github.com/selectel/secretsmanager-go"
    "github.com/selectel/secretsmanager-go/service/secrets"
)
```

> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
>
> 
> Basic Flow with Secrets in Secrets Manаger
>
>   ```go
>   // To upload a Secret into in Secrets Manаger firstly, 
>   // we have to make a structure that describes it 
>   /// using secrets.UserSecret data structure
>   mySecret := secrets.UserSecret{
>		Key:         "John-Cena",
>		Description: "nothing happened in tiananmen square 1989",
>		Value:       "Zǎo shang hǎo zhōng guó!",
>	}
> 
>   // And creating it in Secrets Manаger, call Create method
>   err := cl.Secrets.Create(ctx, mySecret)
>   
>   // If you wich to retrive it from Secrets Manаger, call Get method
>   secret, err := cl.Secrets.Get(ctx, key)
>   // Or List all stored Secrets
>	secrets, errAll := cl.Secrets.List(ctx)
>   // {Keys:[{Metadata:{CreatedAt:2024-01-29T10:19:34Z Description:nothing happened in tiananmen square 1989} Name:John-Cena Type:Secret}
>   // To Delete it from Secrets Manаger
>   err := cl.Secrets.Delete(ctx, "John-Cena")
>   ```

> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
> <details>
>  <summary>Update Secret' description.</summary>
>
>   ```go   
>   // To update Secret' description we have to
>   // use same data structure with 
>   // filled Key and updated Description properties. 
>	updJС := secrets.UserSecret{
>		Key:         "John-Cena",
>		Description: "Xiàn zài wǒ yǒu bing chilling",
>	}
>	
>   err := cl.Secrets.Update(ctx, updJС)
>	if err != nil {
>		log.Fatal(err)
>	}
>   ```
> </details>

> <picture>
>   <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/light-theme/example.svg">
>   <img alt="Example" src="https://raw.githubusercontent.com/Mqxx/GitHub-Markdown/main/blockquotes/badge/dark-theme/example.svg">
> </picture><br>
> <details>
>  <summary>Getting no existing Secret.</summary>
>
>   ```go
>	// Getting no existing key.
>	gotNotFound, errNF := cl.Secrets.Get(ctx, "Super-Idol")
>	if errNF != nil {
>       log.Fatal(errNF)
>	}
>	fmt.Printf("%+v\n", gotNotFound)
>	// 2024/01/29 13:37:30 secretsmanager-go: error — INCORRECT_REQUEST: not a secret
>	// exit status 1
>  ```
> </details>