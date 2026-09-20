package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"
)

type Key struct { ID string; Private *rsa.PrivateKey; ExpiresAt time.Time }
type KeyStore struct { Valid Key; Expired Key }

func NewKeyStore() (*KeyStore, error) {
	valid, err := generateKey("valid-key", time.Now().Add(time.Hour)); if err != nil { return nil, err }
	expired, err := generateKey("expired-key", time.Now().Add(-time.Hour)); if err != nil { return nil, err }
	return &KeyStore{Valid: valid, Expired: expired}, nil
}
func generateKey(id string, exp time.Time) (Key, error) {
	p, err := rsa.GenerateKey(rand.Reader, 2048); if err != nil { return Key{}, err }
	return Key{ID: id, Private: p, ExpiresAt: exp}, nil
}
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func intBytes(i int) []byte { return big.NewInt(int64(i)).Bytes() }
func (k Key) JWK() map[string]string {
	return map[string]string{"kty":"RSA","use":"sig","alg":"RS256","kid":k.ID,"n":b64url(k.Private.PublicKey.N.Bytes()),"e":b64url(intBytes(k.Private.PublicKey.E))}
}
