package authorizer

import (
	"crypto/md5"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// Options ...
type Options struct {
	PrivateKey  string
	PublicKey   string
	TokenSource TokenSource
	Expiry      int
}

// TokenSource ...
type TokenSource struct {
	HeaderKey  string
	QueryKey   string
	AuthBearer bool
}

var (
	// DefaultAuthHeaderKey ...
	DefaultAuthHeaderKey = `X-AuthVerifierToken`
	// DefaultExpiry ...
	DefaultExpiry = 2800 // minutes  ( 2 days default )
	// DefaultGetQueryParam ...
	DefaultGetQueryParam = "verifier"
	// ErrMissingParams ...
	ErrMissingParams = errors.New("missing required parameters")
	// ErrEmptyToken ...
	ErrEmptyToken = errors.New("empty token")
	// ErrInvalidToken ...
	ErrInvalidToken = errors.New("invalid token")
	// ErrConvertClaims ...
	ErrConvertClaims = errors.New("fail convert claims")
)

// AuthClaims custom claims
type AuthClaims struct {
	jwt.StandardClaims             // standard claims
	MetaInfo           interface{} `json:"meta_info,omitempty"`
	Details            *Details    `json:"details,omitempty"`
}

// SetSubject ...
func (s *AuthClaims) SetSubject(salt string) string {
	return fmt.Sprintf("%x",
		md5.Sum([]byte(
			fmt.Sprintf("%s/%d/%s",
				s.Issuer,
				s.ExpiresAt,
				salt)),
		),
	)
}

// CheckSubject ...
func (s *AuthClaims) CheckSubject(salt string) bool {
	return strings.EqualFold(s.SetSubject(salt), s.Subject)
}

// Details ...
type Details struct {
	UUID         string   `json:"uuid,omitempty"`
	AuthToken    string   `json:"auth_token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	AuthType     string   `json:"auth_type,omitempty"`
	Name         string   `json:"name,omitempty"`
	Method       string   `json:"method,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}
