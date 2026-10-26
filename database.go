package main

import (
 "crypto/rand"
 "crypto/rsa"
 "crypto/x509"
 "database/sql"
 "encoding/pem"
 "errors"
 "fmt"
 "strconv"
 "time"

 _ "modernc.org/sqlite"
)

const databaseFile = "totally_not_my_privateKeys.db"

type KeyStore struct { db *sql.DB }
type Key struct { ID string; Private *rsa.PrivateKey; ExpiresAt time.Time }

func NewKeyStore(path string) (*KeyStore, error) {
 db, err := sql.Open("sqlite", path)
 if err != nil { return nil, err }
 db.SetMaxOpenConns(1)
 if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(
 kid INTEGER PRIMARY KEY AUTOINCREMENT,
 key BLOB NOT NULL,
 exp INTEGER NOT NULL
 )`); err != nil { db.Close(); return nil, err }
 store := &KeyStore{db: db}
 if err = store.seed(); err != nil { db.Close(); return nil, err }
 return store, nil
}

func (s *KeyStore) Close() error { return s.db.Close() }

func (s *KeyStore) seed() error {
 now := time.Now().Unix()
 var valid, expired int
 if err := s.db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", now).Scan(&valid); err != nil { return err }
 if err := s.db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= ?", now).Scan(&expired); err != nil { return err }
 if valid == 0 { if err := s.insertKey(time.Now().Add(2*time.Hour)); err != nil { return err } }
 if expired == 0 { if err := s.insertKey(time.Now().Add(-time.Hour)); err != nil { return err } }
 return nil
}

func (s *KeyStore) insertKey(expires time.Time) error {
 private, err := rsa.GenerateKey(rand.Reader, 2048)
 if err != nil { return err }
 encoded := pem.EncodeToMemory(&pem.Block{Type:"RSA PRIVATE KEY", Bytes:x509.MarshalPKCS1PrivateKey(private)})
 _, err = s.db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", encoded, expires.Unix())
 return err
}

func decodeKey(id int64, encoded []byte, exp int64) (Key, error) {
 block, _ := pem.Decode(encoded)
 if block == nil || block.Type != "RSA PRIVATE KEY" { return Key{}, errors.New("invalid RSA private key PEM") }
 private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
 if err != nil { return Key{}, fmt.Errorf("parse RSA key: %w",err) }
 return Key{ID:strconv.FormatInt(id,10),Private:private,ExpiresAt:time.Unix(exp,0)},nil
}

func (s *KeyStore) selectKey(expired bool) (Key,error) {
 query := "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
 if expired { query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1" }
 var id, exp int64
 var encoded []byte
 if err := s.db.QueryRow(query,time.Now().Unix()).Scan(&id,&encoded,&exp); err != nil { return Key{},err }
 return decodeKey(id,encoded,exp)
}

func (s *KeyStore) validKeys() ([]Key,error) {
 rows,err:=s.db.Query("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",time.Now().Unix())
 if err!=nil{return nil,err}
 defer rows.Close()
 keys:=[]Key{}
 for rows.Next() {
  var id,exp int64
  var encoded []byte
  if err:=rows.Scan(&id,&encoded,&exp);err!=nil{return nil,err}
  k,err:=decodeKey(id,encoded,exp);if err!=nil{return nil,err}
  keys=append(keys,k)
 }
 return keys,rows.Err()
}
