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

const HeaderName = "X-Hub-Signature"

var (
	ErrMissingHeader    = errors.New("Missing Header")
	ErrInvalidSignature = errors.New("Invalid Signature")
	ErrMissingBody      = errors.New("Missing Body")
	ErrMethodNotAllowed = errors.New("Method not allowed")
)

type GitHubWebhookAuth struct {
	SecretKey []byte
}

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
