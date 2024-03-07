package authorizer

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// GetPublicKey ...
func GetPublicKey(key string) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		// parse the key
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, errors.New("failed to parse PEM block containing the public key")
		}
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		// check the method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			err = fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			return nil, err
		}
		// good ;-)
		return pub, err
	}
}

// GetTokenFromAuthBearer ...
func GetTokenFromAuthBearer(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return strings.TrimSpace(bearer[7:])
	}
	return ""
}

// GetTokenFromHeader ...
func GetTokenFromHeader(r *http.Request, key string) string {
	return strings.TrimSpace(r.Header.Get(key))
}

// GetTokenFromQuery ...
func GetTokenFromQuery(r *http.Request, key string) string {
	return strings.TrimSpace(r.URL.Query().Get(key))
}
