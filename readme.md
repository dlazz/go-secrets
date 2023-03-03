# Secrets

A simple Go oackage to encrypt strings

## Installation

```sh 
   go get -u github.com/dlazz/go-secrets
```

## Usage

```go
package main

import (
    "github.com/dlazz/go-secrets"
    "log"
    "fmt"
)
var EncriptionKey = "0123456789abcdef"

func main(){
    secrets.Init(EncryptionKey)
    stringToEncrypt = "my_secret_password"

    encryptedString, err := secrets.Manager.Encrypt(stringToEncrypt)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("encrypted secret: ", encryptedString)
    decryptedString, err := secrets.Manager.Decrypt(encryptedString)
        if err != nil {
        log.Fatal(err)
    }
    fmt.Println("original string: ", decryptedString)
}
```

You can embed your encryption key while building, using go ldflags

```sh
	go build  -ldflags="-X 'main.EncryptionKey=xyzxyz1234567890'" 
```
