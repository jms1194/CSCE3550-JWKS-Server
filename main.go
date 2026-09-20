package main

import (
	"log"
	"net/http"
)

func main() {
	store, err := NewKeyStore()
	if err != nil { log.Fatal(err) }
	srv := NewServer(store)
	log.Println("JWKS server listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", srv.Routes()))
}
