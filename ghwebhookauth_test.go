package ghwebhookauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testSecret = "f00b4r"

type testStruct struct {
	Method       string
	HeaderValue  *string
	ExpectedCode int
	ExpectedBody *string
	PostBody     *string
}

func dummyHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func testRequest(t *testing.T, s testStruct) {
	assert := assert.New(t)
	g := New(testSecret)
	assert.NotNil(g)

	m := make(map[string]http.HandlerFunc)
	m["HandlerWithNext"] = func(w http.ResponseWriter, r *http.Request) {
		g.HandlerWithNext(w, r, dummyHandler)
	}
	m["Handler"] = func(w http.ResponseWriter, r *http.Request) {
		g.Handler(http.HandlerFunc(dummyHandler)).ServeHTTP(w, r)
	}

	for k, v := range m {
		t.Logf("Testing %s\n", k)
		var body io.Reader
		if s.PostBody != nil {
			body = strings.NewReader(*s.PostBody)
		}
		req, err := http.NewRequest(s.Method, "http://localhost/foobar", body)
		if err != nil {
			t.Fatal(err)
		}
		if s.HeaderValue != nil {
			req.Header.Set(HeaderName, *s.HeaderValue)
		}
		w := httptest.NewRecorder()
		v(w, req)
		assert.Equal(w.Code, s.ExpectedCode)
		if s.ExpectedBody != nil {
			assert.Equal(*s.ExpectedBody, string(w.Body.Bytes()))
		}
	}
}

func TestDisallowedMethods(t *testing.T) {
	disallow := []string{"GET", "PUT", "DELETE", "PATCH", "HEAD"}
	for _, m := range disallow {
		testRequest(t, testStruct{Method: m, ExpectedCode: 405})
	}
}

func TestEmptyPost(t *testing.T) {
	expectedBody := "Missing Body\n"
	testRequest(t, testStruct{Method: "POST", ExpectedCode: 400, ExpectedBody: &expectedBody})
}

func TestMissingHeader(t *testing.T) {
	expectedBody := "Missing Header\n"
	postBody := "foobar"
	testRequest(t, testStruct{Method: "POST", ExpectedCode: 400, ExpectedBody: &expectedBody, PostBody: &postBody})
}

func TestEmptyHeader(t *testing.T) {
	expectedBody := "Missing Header\n"
	postBody := "foobar"
	headerValue := ""
	testRequest(t, testStruct{Method: "POST", ExpectedCode: 400, ExpectedBody: &expectedBody, PostBody: &postBody, HeaderValue: &headerValue})
}

func TestInvalidSignature(t *testing.T) {
	expectedBody := ErrInvalidSignature.Error() + "\n"
	postBody := "foobar"
	headerValue := "dummyvalue"
	testRequest(t, testStruct{Method: "POST", ExpectedCode: 400, ExpectedBody: &expectedBody, PostBody: &postBody, HeaderValue: &headerValue})
}

func TestValidRequest(t *testing.T) {
	expectedBody := "OK"
	postBody := "foobar"

	digest := hmac.New(sha1.New, []byte(testSecret))
	digest.Write([]byte(postBody))
	b := bytes.NewBufferString("sha1=" + hex.EncodeToString(digest.Sum(nil)))

	headerValue := string(b.Bytes())
	testRequest(t, testStruct{Method: "POST", ExpectedCode: 200, ExpectedBody: &expectedBody, PostBody: &postBody, HeaderValue: &headerValue})

	/*
		assert := assert.New(t)
		g := New("mys3cr3t")
		assert.NotNil(g)

		w := httptest.NewRecorder()
		body := strings.NewReader("body")
		req, err := http.NewRequest("POST", "http://localhost/foobar", body)
		if err != nil {
			t.Fatal(err)
		}

		digest := hmac.New(sha1.New, []byte("testSecret"))
		digest.Write([]byte("body"))
		if err != nil {
			t.Fatal(err)
		}
		b := bytes.NewBufferString("sha1=" + hex.EncodeToString(digest.Sum(nil)))

		req.Header.Set(HeaderName, string(b.Bytes()))
		g.HandlerWithNext(w, req, dummyHandler)
		assert.Equal(w.Code, 200, "Empty body returns 200")
		assert.Equal(string(w.Body.Bytes()), "OK", "Should equal invalid signature")
	*/
}
