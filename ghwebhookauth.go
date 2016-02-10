package ghwebhookauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
)

// HeaderName is the name of the header containing the signature GitHub sends
const HeaderName = "X-Hub-Signature"

var (
	// Error condition when a request is missing a header
	ErrMissingHeader    = errors.New("Missing Header")
	// Error condition when a request has a header but the contents are invalid
	ErrInvalidSignature = errors.New("Invalid Signature")
	// Error condition when a request has no body
	ErrMissingBody      = errors.New("Missing Body")
	// Error condition when a request has an invalid method
	ErrMethodNotAllowed = errors.New("Method not allowed")
)

type GitHubWebhookAuth struct {
	SecretKey []byte
}

// New returns an instance of GitHubWebhookAuth middleware
func New(secretKey string) *GitHubWebhookAuth {
	return &GitHubWebhookAuth{[]byte(secretKey)}
}

func (g *GitHubWebhookAuth) check(r *http.Request) error {

	if r.Method != "POST" {
		return ErrMethodNotAllowed
	}
	if r.ContentLength == 0 {
		return ErrMissingBody
	}

	h := r.Header.Get(HeaderName)
	if h == "" {
		return ErrMissingHeader
	}

	digest := hmac.New(sha1.New, g.SecretKey)
	_, err := io.Copy(digest, r.Body)

	if err != nil {
		return err
	}

	b := bytes.NewBufferString("sha1=" + hex.EncodeToString(digest.Sum(nil)))

	if !hmac.Equal(b.Bytes(), []byte(h)) {
		return ErrInvalidSignature
	}

	return nil
}

// HandlerWithNext is a Negroni compatible middleware function
func (g *GitHubWebhookAuth) HandlerWithNext(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	err := g.check(r)

	if err != nil {
		status := 400
		if err == ErrMethodNotAllowed {
			status = 405
		}
		http.Error(w, err.Error(), status)
		return
	}

	if next != nil {
		next(w, r)
	}
}

// Handler returns net/http compatible middleware handler 
func (g *GitHubWebhookAuth) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := g.check(r)

		if err != nil {
			status := 400
			if err == ErrMethodNotAllowed {
				status = 405
			}
			http.Error(w, err.Error(), status)
			return
		}

		h.ServeHTTP(w, r)
	})
}
