# Basic JWKS Server

A small Go implementation of the CSCE 3550 basic JWKS server assignment.

## Features

- RSA-2048 key generation at startup
- Unique `kid` values and expiration timestamps
- `GET /.well-known/jwks.json` returns only unexpired public keys
- `POST /auth` returns an RS256-signed JWT
- `POST /auth?expired` returns a JWT signed by the expired key with an expired `exp`
- Unit tests and Go coverage support

## Requirements

- Go 1.23+ (the code uses only the Go standard library)

## Run

```bash
go run .
```

The server listens on port `8080`.

## Manual checks

```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST 'http://localhost:8080/auth?expired'
```

## Tests and coverage

```bash
go test ./...
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

Take a screenshot showing the coverage percentage and your identifying information as required by the assignment.

## Official test client

Download the CSCE 3550 `gradebot` release for your operating system. With this server running, run the Project 1 client against port 8080 according to the course release instructions. Take a screenshot of the successful result with the identifying information required by the assignment.

## Notes

This project intentionally mocks authentication. `/auth` requires no request body. Private RSA key material is never returned by the JWKS endpoint.
