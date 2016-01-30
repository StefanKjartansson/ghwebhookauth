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
)

type GitHubWebhookAuth struct {
	SecretKey []byte
}

func New(secretKey string) *GitHubWebhookAuth {
	return &GitHubWebhookAuth{[]byte(secretKey)}
}

func (g *GitHubWebhookAuth) authenticate(r *http.Request) error {

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

func (g *GitHubWebhookAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.ContentLength == 0 {
		http.Error(w, "Empty body", 400)
		return
	}
	err := g.authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if next != nil {
		next(w, r)
	}
}
