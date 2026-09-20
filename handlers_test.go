package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)
func setup(t *testing.T)(*Server,*KeyStore){t.Helper();k,e:=NewKeyStore();if e!=nil{t.Fatal(e)};return NewServer(k),k}
func TestJWKSOnlyValid(t *testing.T){s,k:=setup(t);r:=httptest.NewRequest(http.MethodGet,"/.well-known/jwks.json",nil);w:=httptest.NewRecorder();s.Routes().ServeHTTP(w,r);if w.Code!=200{t.Fatalf("status %d",w.Code)};var body struct{Keys []map[string]string `json:"keys"`};if err:=json.Unmarshal(w.Body.Bytes(),&body);err!=nil{t.Fatal(err)};if len(body.Keys)!=1||body.Keys[0]["kid"]!=k.Valid.ID{t.Fatalf("unexpected keys: %#v",body.Keys)};if body.Keys[0]["n"]==""||body.Keys[0]["e"]==""{t.Fatal("missing RSA public parameters")};if strings.Contains(w.Body.String(),"PRIVATE"){t.Fatal("private material leaked")}}
func TestAuthValidAndExpired(t *testing.T){s,k:=setup(t);for _,tc:=range []struct{url,kid string;expired bool}{{"/auth",k.Valid.ID,false},{"/auth?expired",k.Expired.ID,true}}{w:=httptest.NewRecorder();s.Routes().ServeHTTP(w,httptest.NewRequest(http.MethodPost,tc.url,nil));if w.Code!=200{t.Fatalf("%s status %d",tc.url,w.Code)};parts:=strings.Split(strings.TrimSpace(w.Body.String()),".");if len(parts)!=3{t.Fatal("not JWT")};decode:=func(part string)map[string]any{b,e:=base64.RawURLEncoding.DecodeString(part);if e!=nil{t.Fatal(e)};var m map[string]any;if e=json.Unmarshal(b,&m);e!=nil{t.Fatal(e)};return m};h,c:=decode(parts[0]),decode(parts[1]);if h["kid"]!=tc.kid||h["alg"]!="RS256"{t.Fatalf("bad header %#v",h)};exp:=int64(c["exp"].(float64));if tc.expired&&exp>=time.Now().Unix(){t.Fatal("expected expired")};if !tc.expired&&exp<=time.Now().Unix(){t.Fatal("expected unexpired")}}}
func TestMethods(t *testing.T){s,_:=setup(t);for _,tc:=range []struct{method,url string}{{http.MethodGet,"/auth"},{http.MethodPost,"/.well-known/jwks.json"}}{w:=httptest.NewRecorder();s.Routes().ServeHTTP(w,httptest.NewRequest(tc.method,tc.url,nil));if w.Code!=http.StatusMethodNotAllowed{t.Fatalf("wanted 405 got %d",w.Code)}}}
func TestJWKEncodingAndSign(t *testing.T){_,k:=setup(t);j:=k.Valid.JWK();if j["kty"]!="RSA"||j["use"]!="sig"||j["alg"]!="RS256"{t.Fatal(j)};if _,e:=signJWT(k.Valid,map[string]any{"exp":time.Now().Add(time.Hour).Unix()});e!=nil{t.Fatal(e)}}
