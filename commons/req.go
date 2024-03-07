package commons

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	// AppVersion ...
	AppVersion = "v1.0"
	// AppName ...
	AppName = "BayugismoHttpClientApp"
	// DefaultJSONHeader ...
	DefaultJSONHeader = "application/json" // "application/vnd.api+json"
	// DefaultAPIJSONHeader ...
	DefaultAPIJSONHeader = "application/vnd.api+json"
	// DefaultFormHeader ...
	DefaultFormHeader = "application/x-www-form-urlencoded"
	// DefaultXMLHeader ...
	DefaultXMLHeader = "application/xml"
	// DefaultNamespace ...
	DefaultNamespace = "Bayugismo-Space"
	// DefaultTimeout ....
	DefaultTimeout = 60
	// DefaultUserAgent ...
	DefaultUserAgent = fmt.Sprintf("%s %s/%s",
		strings.ReplaceAll(DefaultNamespace, "-", ""),
		AppName, AppVersion)
)

// ReqParams ...
type ReqParams struct {
	Form        []byte
	Signed      string
	QueryParams string
	Path        string
	Headers     map[string]string
	ContentType string
	FormData    string
}

// Raw ...
type Raw interface{}

// SendRequest ...
func SendRequest(ctx context.Context, client *http.Client, link, method string, params *ReqParams) (int, []byte, error) {

	var (
		req *http.Request
		err error
	)

	// query string
	if len(params.QueryParams) > 0 {
		if !strings.Contains(link, `?`) {
			link = fmt.Sprintf("%s?%s", link, strings.TrimPrefix(params.QueryParams, `?`))
		} else {
			link = fmt.Sprintf("%s&%s", link, strings.TrimPrefix(params.QueryParams, `&`))
		}
	}

	if len(params.FormData) > 0 {
		req, err = http.NewRequestWithContext(
			ctx,
			method,
			link,
			strings.NewReader(params.FormData))
	} else {
		req, err = http.NewRequestWithContext(
			ctx,
			method,
			link,
			bytes.NewReader(params.Form))
	}

	if err != nil {
		return http.StatusUnprocessableEntity, nil, err
	}

	// add headers if any
	for k, v := range params.Headers {
		req.Header.Set(k, v)
	}

	// default
	if len(req.Header.Get("Content-Type")) <= 0 {
		req.Header.Set("Content-Type", DefaultJSONHeader)
	}

	// NOTE this !!! (stackoverflow)
	req.Close = true

	// Make request
	ret, err := client.Do(req)
	if err != nil {
		return http.StatusUnprocessableEntity, nil, err
	}

	var (
		body []byte
		iErr error
	)

	if ret != nil && ret.Body != nil {

		defer func() {
			_ = ret.Body.Close()
		}()

		body, iErr = ioutil.ReadAll(ret.Body)
		if iErr != nil {
			return ret.StatusCode, nil, iErr
		}
	}

	if os.Getenv("DBE_LIBRARY_DEBUG") == "1" {
		// dump the raw here
		var raw Raw
		if strings.EqualFold(ret.Header.Get("Content-Type"), DefaultXMLHeader) {
			raw = string(body)
		} else {
			_ = json.Unmarshal(body, &raw)
		}

		logrus.Println(
			ret.Header.Get("Content-Type"),
			"raw_response",
			ret.StatusCode,
			Stringify(raw))
	}
	// good
	return ret.StatusCode, body, nil
}
