package main

import (
 "encoding/base64"
 "math/big"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func intBytes(i int) []byte { return big.NewInt(int64(i)).Bytes() }
func (k Key) JWK() map[string]string {
 return map[string]string{"kty":"RSA","use":"sig","alg":"RS256","kid":k.ID,"n":b64url(k.Private.PublicKey.N.Bytes()),"e":b64url(intBytes(k.Private.PublicKey.E))}
}
