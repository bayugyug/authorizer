# authorizer

## Package can securely sign / un-sign a request payload 
	- Prerequisite must have a valid RSA private/public certificates



## Badge
[![build](https://github.com/bayugyug/authorizer/actions/workflows/ci.yml/badge.svg)](https://github.com/bayugyug/authorizer/actions/workflows/ci.yml)


### How to use the package
```go

import (
   "fmt"
   	"log"
   	"net/http"
   	"net/url"
   	"time"
   
   	"github.com/dgrijalva/jwt-go"
   	"github.com/go-chi/chi"
   	"github.com/go-chi/render"
   	"github.com/google/uuid"
   
   	"github.com/bayugyug/authorizer"
   	"github.com/bayugyug/authorizer/commons"
)

```


### How to sign a payload

```go

// salt, publicKey, privateKey
    
    
opts := authorizer.Options{
    PrivateKey: privKeyStr,
    PublicKey:  pubKeyStr,
    TokenSource: authorizer.TokenSource{
        QueryKey: "_verify",
    },
    Expiry: 1400,
}

verifier = authorizer.NewVerifierService(&opts)

claims := &authorizer.AuthClaims{
    StandardClaims: jwt.StandardClaims{
    Audience:  "source-verifier-aud",
    Id:        uuid.New().String(),
    Issuer:    "source-verifier-issuer",
    Subject:   salt,                                                     // salt
    ExpiresAt: time.Now().Add(time.Duration(3600) * time.Minute).Unix(), // expiry
    },
    MetaInfo: map[string]interface{}{
        "extra": uuid.New().String(),
    },
}

// sign
sign, err := verifier.Sign(claims)

if err != nil {
    fmt.Println("fail",err)
    return
}


```


### How to un-sign a payload

```go

// salt, publicKey, privateKey
// these variables should be in config file & in the S3 config for ( private & secrets )
    
    
opts := authorizer.Options{
    PrivateKey: privKeyStr,
    PublicKey:  pubKeyStr,
    TokenSource: authorizer.TokenSource{
        QueryKey: "_verify",
    },
    Expiry: 1400,
}

verifier = authorizer.NewVerifierService(&opts)
    
     
// handler
proxyHandler := func(w http.ResponseWriter, r *http.Request) {
    // un-sign jwt
    res, err := verifier.UnSign(r)
    if err != nil {
        render.Status(r, http.StatusInternalServerError)
        render.JSON(w, r,
            err.Error(),
        )
        return
    }

    // extra check the salt via the subject
    oks := res.CheckSubject(salt)
   
    commons.JSONify("check subject/salt", res, oks)

    if !oks {
        render.Status(r, http.StatusInternalServerError)
        render.JSON(w, r,
            err.Error(),
        )
        return
    }
}



```

### Self sign RSA certificates
```shell script

# init vars
mkdir -p ~/tmp/ 2>/dev/null
PREFIX=$(date '+%Y-%m-%d-%H%M%S')-$(printf "%04x-%04x" ${RANDOM} ${RANDOM})
PRIVKEY=~/tmp/${PREFIX}-priv.pem
CACERT=~/tmp/${PREFIX}-cacert.pem
DERCERT=~/tmp/${PREFIX}-dercert.cer
PUBKEY=~/tmp/${PREFIX}-pub.txt

# generate
openssl genrsa -out $PRIVKEY
openssl req -new -x509 -key $PRIVKEY -out $CACERT -days 365 -subj "/C=SG/ST='Singapore'/L='Singapore/O=Bayugismo/OU='Engineering'/CN=*.bayugismo.space"
openssl x509 -inform PEM -in $CACERT -outform DER -out $DERCERT
openssl x509 -inform der -in $DERCERT -noout -pubkey > $PUBKEY

# PUBLIC KEY
openssl rsa -pubin -in $PUBKEY -RSAPublicKey_out | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'


# PRIVATE KEY
cat $PRIVKEY | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'

```
