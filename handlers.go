package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type Server struct{ keys *KeyStore }

func NewServer(k *KeyStore) *Server { return &Server{keys: k} }
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.jwks)
	mux.HandleFunc("/auth", s.auth)
	return mux
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stored, err := s.keys.validKeys()
	if err != nil {
		http.Error(w, "unable to read keys", http.StatusInternalServerError)
		return
	}
	keys := make([]map[string]string, 0, len(stored))
	for _, k := range stored {
		keys = append(keys, k.JWK())
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, expired := r.URL.Query()["expired"]
	key, err := s.keys.selectKey(expired)
	if err != nil {
		http.Error(w, "unable to read signing key", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	if expired {
		exp = now.Add(-time.Hour).Unix()
	}
	token, err := signJWT(key, map[string]any{"sub": "userABC", "iat": now.Unix(), "exp": exp})
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}
func signJWT(key Key, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": key.ID}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	input := enc(h) + "." + enc(p)
	digest := sha256.Sum256([]byte(input))
	sig, err := key.Private.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{input, enc(sig)}, "."), nil
}
