# Error Handling
In generall, `secretsmanager-go` errors can be divided into two types:
- Server Errors: returned by the Secret Manager Service itself
- Client Errors: returned by the `secretsmanager-go` (this package)

Any of these can be handled as a special type [secretsmanagererrors.Error](../secretsmanagererrors/secretsmanagererrors.go):

Below there's an example on how to handle these errors:

> [!NOTE]
> You can use `errors.Is` to identify the type > of an error:
> 
>   ```go
>   if err != nil {
>       switch {
>       case errors.Is(err, secretsmanagererrors.ErrClientNoAuthOpts):
>           log.Fatalf("No rights: %s", err.Error())
>    }
>    // ...
>   }
>   ```

> [!IMPORTANT]
> You can cast a returned error to `secretsmanagererrors.Error` with `errors.As` and get the specific info (description of an error, for example):
> ```go
>   if err != nil {
>       var smError *secretsmanagererrors.Error
>       if errors.As(err, &smError) {
>           log.Fatalf("SecretsManager Error! Description: %s", smError.Desc())
>       }
>       // ...
>   }
> ```