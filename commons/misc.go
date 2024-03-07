package commons

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"reflect"
	"time"
)

// FormatAmountToCents ...
func FormatAmountToCents(m float64) int64 {
	return int64((math.Round(m*100) / 100) * 100)
}

// NoOpTraceContext default ctx
func NoOpTraceContext() context.Context {
	return context.Background()
}

// ToDecimal ...
func ToDecimal(param interface{}) (float64, error) {
	floatType := reflect.TypeOf(float64(0))
	v := reflect.ValueOf(param)
	v = reflect.Indirect(v)
	if !v.Type().ConvertibleTo(floatType) {
		return 0, fmt.Errorf("cannot convert %v to float64", v.Type())
	}
	fv := v.Convert(floatType)
	return fv.Float(), nil
}

// ToString ...
func ToString(param interface{}, def string) string {
	if s, oks := param.(string); oks {
		return s
	}
	return def

}

// DefaultHTTPClient ...
func DefaultHTTPClient(timeout int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			Dial: (&net.Dialer{
				Timeout:   time.Duration(timeout) * time.Second,
				KeepAlive: 0,
			}).Dial,
			TLSHandshakeTimeout:   time.Duration(timeout) * time.Second, // 30 secs
			MaxIdleConns:          100,
			IdleConnTimeout:       24 * time.Hour,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}
}

// GetIP ...
func GetIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-FORWARDED-FOR"); forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
}
