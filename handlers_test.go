package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T) (*Server, *KeyStore) {
	t.Helper()
	k, e := NewKeyStore(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = k.Close() })
	return NewServer(k), k
}
func request(s *Server, method, url string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, httptest.NewRequest(method, url, nil))
	return w
}
func decodePart(t *testing.T, part string) map[string]any {
	t.Helper()
	b, e := base64.RawURLEncoding.DecodeString(part)
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	return m
}
func TestJWKSOnlyValid(t *testing.T) {
	s, k := setup(t)
	w := request(s, http.MethodGet, "/.well-known/jwks.json")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("expected one valid key: %#v", body.Keys)
	}
	valid, err := k.selectKey(false)
	if err != nil {
		t.Fatal(err)
	}
	if body.Keys[0]["kid"] != valid.ID || body.Keys[0]["n"] == "" || body.Keys[0]["e"] == "" {
		t.Fatalf("bad JWK %#v", body.Keys[0])
	}
	if strings.Contains(w.Body.String(), "PRIVATE") {
		t.Fatal("private material leaked")
	}
	if body.Keys[0]["kty"] != "RSA" || body.Keys[0]["alg"] != "RS256" || body.Keys[0]["use"] != "sig" {
		t.Fatal(body.Keys)
	}
}
func TestAuthValidAndExpired(t *testing.T) {
	s, k := setup(t)
	for _, tc := range []struct {
		url     string
		expired bool
	}{{"/auth", false}, {"/auth?expired", true}, {"/auth?expired=false", true}} {
		w := request(s, http.MethodPost, tc.url)
		if w.Code != 200 {
			t.Fatalf("%s status %d: %s", tc.url, w.Code, w.Body.String())
		}
		parts := strings.Split(strings.TrimSpace(w.Body.String()), ".")
		if len(parts) != 3 {
			t.Fatal("not JWT")
		}
		header, claims := decodePart(t, parts[0]), decodePart(t, parts[1])
		key, err := k.selectKey(tc.expired)
		if err != nil {
			t.Fatal(err)
		}
		if header["kid"] != key.ID || header["alg"] != "RS256" {
			t.Fatalf("bad header %#v", header)
		}
		exp := int64(claims["exp"].(float64))
		if tc.expired && exp >= time.Now().Unix() {
			t.Fatal("expected expired JWT")
		}
		if !tc.expired && exp <= time.Now().Unix() {
			t.Fatal("expected valid JWT")
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.Private.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatal(err)
		}
	}
}
func TestMethods(t *testing.T) {
	s, _ := setup(t)
	for _, tc := range []struct{ method, url string }{{http.MethodGet, "/auth"}, {http.MethodPost, "/.well-known/jwks.json"}} {
		w := request(s, tc.method, tc.url)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("wanted 405 got %d", w.Code)
		}
	}
}
func TestDatabasePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	first, err := NewKeyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := first.selectKey(false)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := first.selectKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewKeyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, err := second.selectKey(false)
	if err != nil {
		t.Fatal(err)
	}
	old, err := second.selectKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != valid.ID || old.ID != expired.ID {
		t.Fatal("keys changed after restart")
	}
	if after.Private.PublicKey.N.Cmp(valid.Private.PublicKey.N) != 0 {
		t.Fatal("key material changed")
	}
}
func TestDatabaseErrors(t *testing.T) {
	s, k := setup(t)
	if _, err := decodeKey(1, []byte("not PEM"), 0); err == nil {
		t.Fatal("expected bad PEM error")
	}
	if _, err := decodeKey(1, []byte("-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----"), 0); err == nil {
		t.Fatal("expected bad DER error")
	}
	if _, err := strconv.Atoi("not-an-int"); err == nil {
		t.Fatal("sanity check")
	}
	if _, err := k.db.Exec("DELETE FROM keys"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.selectKey(false); err == nil {
		t.Fatal("expected missing key error")
	}
	if _, err := k.selectKey(true); err == nil {
		t.Fatal("expected missing expired key error")
	}
	if err := k.db.Close(); err != nil {
		t.Fatal(err)
	}
	if w := request(s, http.MethodGet, "/.well-known/jwks.json"); w.Code != 500 {
		t.Fatal(w.Code)
	}
	if w := request(s, http.MethodPost, "/auth"); w.Code != 500 {
		t.Fatal(w.Code)
	}
}
func TestAdditionalValidKey(t *testing.T) {
	s, k := setup(t)
	if err := k.insertKey(time.Now().Add(3 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	keys, err := k.validKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(keys))
	}
	w := request(s, http.MethodGet, "/.well-known/jwks.json")
	var result struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Keys) != 2 {
		t.Fatal(result.Keys)
	}
}
