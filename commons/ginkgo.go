package commons

import (
	"bytes"
	"io"
	ioutil "io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"

	"os"

	"github.com/gabriel-vasile/mimetype"
	"github.com/go-chi/chi"
	"github.com/onsi/ginkgo/v2"
	log "github.com/sirupsen/logrus"
)

// HTTPDummyReq dummy recorder for http
func HTTPDummyReq(router *chi.Mux, method, path string, hdrs map[string]string,
	body io.Reader) (*httptest.ResponseRecorder, []byte) {
	req, err := http.NewRequest(method, path, body)
	if err != nil {
		ginkgo.Fail(err.Error())
	}
	w := httptest.NewRecorder()
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	router.ServeHTTP(w, req)
	respBody, err := io.ReadAll(w.Body)
	if err != nil {
		ginkgo.Fail(err.Error())
	}
	return w, respBody
}

// HTTPDummyRouting dummy routing for http
func HTTPDummyRouting(handler http.Handler, method, path string, hdrs map[string]string,
	body io.Reader) (string, int) {
	ts := httptest.NewServer(handler)
	defer ts.Close()
	req, err := http.NewRequest(method, ts.URL+""+path, body)
	if err != nil {
		ginkgo.Fail(err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		if resp != nil {
			contents, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Println("Failed", err)
			}
			_ = resp.Body.Close()
			return strings.TrimSpace(string(contents)), resp.StatusCode
		}
		return "", -1
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ginkgo.Fail(err.Error())
	}
	return strings.TrimSpace(string(contents)), resp.StatusCode
}

// DummyUpload ...
func DummyUpload(router *chi.Mux, uriPath, paramName, fileName, formType string) (*httptest.ResponseRecorder, []byte, error) {

	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}

	bodyPart := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyPart)
	part, err := writer.CreateFormFile(paramName, filepath.Base(fileName))
	if err != nil {
		return nil, nil, err
	}

	_, err = io.Copy(part, bytes.NewReader(contents))
	if err != nil {
		return nil, nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, nil, err
	}

	mimeType := mimetype.Detect(contents)

	log.Println("mimeType", mimeType)
	contentType := writer.FormDataContentType()
	if formType != "" {
		contentType = formType
	}
	w, b := HTTPDummyReq(router,
		http.MethodPost,
		uriPath,
		map[string]string{
			"Content-Type": contentType,
		},
		bodyPart)
	return w, b, nil
}

// HTTPRoundTripFunc ...
type HTTPRoundTripFunc func(r *http.Request) (*http.Response, error)

// RoundTrip ...
func (s HTTPRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return s(r)
}
