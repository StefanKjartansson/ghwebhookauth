package ghwebhookauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func dummyHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func TestNew(t *testing.T) {
	assert := assert.New(t)
	g := New("mys3cr3t")
	assert.NotNil(g)
}

func TestDisallowedMethods(t *testing.T) {
	assert := assert.New(t)
	g := New("mys3cr3t")
	assert.NotNil(g)

	disallow := []string{"GET", "PUT", "DELETE", "PATCH", "HEAD"}

	for _, m := range disallow {
		w := httptest.NewRecorder()
		req, err := http.NewRequest(m, "http://localhost/foobar", nil)
		if err != nil {
			t.Fatal(err)
		}
		g.ServeHTTP(w, req, dummyHandler)
		assert.Equal(w.Code, 405, "Disallowed methods should return 405")
	}

}

func TestEmptyPost(t *testing.T) {
	assert := assert.New(t)
	g := New("mys3cr3t")
	assert.NotNil(g)

	w := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "http://localhost/foobar", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderName, "dummyvalue")
	g.ServeHTTP(w, req, dummyHandler)
	assert.Equal(w.Code, 400, "Empty body returns 400")
}

func TestMissingHeader(t *testing.T) {
	assert := assert.New(t)
	g := New("mys3cr3t")
	assert.NotNil(g)

	w := httptest.NewRecorder()
	body := strings.NewReader("body")
	req, err := http.NewRequest("POST", "http://localhost/foobar", body)
	if err != nil {
		t.Fatal(err)
	}
	g.ServeHTTP(w, req, dummyHandler)
	assert.Equal(w.Code, 400, "Missing header returns 400")
	assert.Equal(string(w.Body.Bytes()), ErrMissingHeader.Error()+"\n", "Should equal missing header")
}

func TestEmptyHeader(t *testing.T) {
	assert := assert.New(t)
	g := New("mys3cr3t")
	assert.NotNil(g)

	w := httptest.NewRecorder()
	body := strings.NewReader("body")
	req, err := http.NewRequest("POST", "http://localhost/foobar", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderName, "")
	g.ServeHTTP(w, req, dummyHandler)
	assert.Equal(w.Code, 400, "Missing header returns 400")
	assert.Equal(string(w.Body.Bytes()), ErrMissingHeader.Error()+"\n", "Should equal missing header")
}

func TestInvalidSignature(t *testing.T) {
	assert := assert.New(t)
	g := New("mys3cr3t")
	assert.NotNil(g)

	w := httptest.NewRecorder()
	body := strings.NewReader("body")
	req, err := http.NewRequest("POST", "http://localhost/foobar", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderName, "dummyvalue")
	g.ServeHTTP(w, req, dummyHandler)
	assert.Equal(w.Code, 400, "Empty body returns 400")
	assert.Equal(string(w.Body.Bytes()), ErrInvalidSignature.Error()+"\n", "Should equal invalid signature")
}

func TestValidRequest(t *testing.T) {
	assert := assert.New(t)
	g := New("mys3cr3t")
	assert.NotNil(g)

	w := httptest.NewRecorder()
	body := strings.NewReader("body")
	req, err := http.NewRequest("POST", "http://localhost/foobar", body)
	if err != nil {
		t.Fatal(err)
	}

	digest := hmac.New(sha1.New, []byte("mys3cr3t"))
	digest.Write([]byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	b := bytes.NewBufferString("sha1=" + hex.EncodeToString(digest.Sum(nil)))

	req.Header.Set(HeaderName, string(b.Bytes()))
	g.ServeHTTP(w, req, dummyHandler)
	assert.Equal(w.Code, 200, "Empty body returns 200")
	assert.Equal(string(w.Body.Bytes()), "OK", "Should equal invalid signature")
}
