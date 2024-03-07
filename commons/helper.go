package commons

import (
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// RandString gen uniq string
func RandString(n int) string {
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

// ParamQuery get parameter from req
func ParamQuery(r *http.Request, key string) string {
	q := r.URL.Query()
	return strings.TrimSpace(q.Get(key))
}

// ParamQueryInt get parameter from req
func ParamQueryInt(r *http.Request, key string, def int64) int64 {
	q := r.URL.Query()
	v, err := strconv.ParseInt(strings.TrimSpace(q.Get(key)), 10, 64)
	if v <= 0 || err != nil {
		return def
	}
	return v
}

// ConvertStr2Time convert the param str to time
func ConvertStr2Time(str string) *time.Time {
	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil
	}
	return &t
}

// ConvertStr2TimeRFC3339 convert the param str to time
func ConvertStr2TimeRFC3339(str string) *time.Time {
	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil
	}
	return &t
}

// WrapperInt64Ptr ...
func WrapperInt64Ptr(str int64) *int64 {
	t := int64(str)
	return &t
}

// FormatVaultVal ...
func FormatVaultVal(raw string) (ret string) {
	ret = strings.TrimSpace(
		strings.Replace(
			raw,
			"\\n",
			"\n", -1))
	return
}

// ParamQueryBool ...
func ParamQueryBool(r *http.Request, key string, def bool) bool {
	q := r.URL.Query()
	v := strings.ToLower(strings.TrimSpace(q.Get(key)))
	switch v {
	case "true", "1":
		return true
	case "false", "0":
		return false
	}
	return def
}

// ParamQueryStr ...
func ParamQueryStr(r *http.Request, key string, def string) string {
	q := r.URL.Query()
	v := strings.TrimSpace(q.Get(key))
	if v != "" {
		return v
	}
	return def
}

// FormatConfigFromEnvt ...
func FormatConfigFromEnvt(raw string) string {
	return strings.TrimSpace(
		strings.Replace(
			raw,
			"\\n",
			"\n", -1))
}

// GetMetadata ...
func GetMetadata(metadata interface{}, field string) interface{} {
	m, _ := metadata.(map[string]interface{})
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}
