package authorizer

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/bayugyug/commons"
)

//go:generate mockgen -destination ./mock/mock_verifiersvccreator.go -package mock github.com/bayugyug/authorizer VerifierServiceCreator

// VerifierServiceCreator  ...
type VerifierServiceCreator interface {
	Sign(payload *AuthClaims) (string, error)
	UnSign(req *http.Request) (*AuthClaims, error)
}

// VerifierService  ...
type VerifierService struct {
	opts *Options
}

// NewVerifierService create a service
func NewVerifierService(opts *Options) VerifierServiceCreator {
	// default
	svc := &VerifierService{
		opts: opts,
	}
	if svc.opts.Expiry <= 0 {
		svc.opts.Expiry = DefaultExpiry
	}
	return svc
}

// Sign ... sign the payload
func (s *VerifierService) Sign(payload *AuthClaims) (string, error) {

	// new claims
	if payload == nil {
		return "", ErrMissingParams
	}

	// re calculate the secret-salt
	if payload.Subject != "" {
		payload.Subject = payload.SetSubject(payload.Subject)
	}

	// set default
	if payload.ExpiresAt == 0 {
		payload.ExpiresAt = time.Now().Add(time.Duration(s.opts.Expiry) * time.Minute).Unix()
	}

	// parse private-key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(
		[]byte(commons.FormatConfigFromEnvt(s.opts.PrivateKey)),
	)
	if err != nil {
		return "", err
	}

	// sign with HS256
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = payload

	// sign
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	// nice ;-)
	return tokenString, nil
}

// UnSign ... verify the signed payload
func (s *VerifierService) UnSign(req *http.Request) (*AuthClaims, error) {

	var tokenStr string

	// from bearer
	if s.opts.TokenSource.AuthBearer {
		tokenStr = GetTokenFromAuthBearer(req)
	}
	// from header
	if s.opts.TokenSource.HeaderKey != "" && len(tokenStr) <= 0 {
		tokenStr = GetTokenFromHeader(req, s.opts.TokenSource.HeaderKey)
	}
	// from get-query-string
	if s.opts.TokenSource.QueryKey != "" && len(tokenStr) <= 0 {
		tokenStr = GetTokenFromQuery(req, s.opts.TokenSource.QueryKey)
	}

	// sanity
	if tokenStr == "" {
		return nil, ErrEmptyToken
	}

	// parse it
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&AuthClaims{},
		GetPublicKey(commons.FormatConfigFromEnvt(s.opts.PublicKey)))

	// sanity
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// convert
	newClaims, ok := token.Claims.(*AuthClaims)
	if !ok {
		return nil, ErrConvertClaims
	}

	// good ;-)
	return newClaims, nil

}
