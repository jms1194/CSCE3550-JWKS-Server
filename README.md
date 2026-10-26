# CSCE 3550 — JWKS Server (Project 2)

This Go server implements RS256 JWT issuance and a public JWKS endpoint, with private RSA keys persisted in a local SQLite database.

## Requirements

- Go 1.23.2 or later
- Internet access for the initial Go dependency download

## Run

From the repository root:

```powershell
go mod tidy
go run .
```

The server listens on port 8080. Run it from the repository root so that `totally_not_my_privateKeys.db` is created in the current working directory, where Gradebot expects it.

The database has the exact schema:

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
```

At startup, the server seeds a valid key and an expired key if the corresponding type is missing. Existing keys persist across restarts. Keys are stored as PKCS#1 PEM in SQLite BLOBs, and all variable SQL values use parameterized queries.

## Endpoints

- `GET /.well-known/jwks.json` returns public RSA parameters for unexpired keys only.
- `POST /auth` issues an RS256 JWT signed by an unexpired key.
- `POST /auth?expired` issues an already-expired JWT signed by an expired key.

Authentication is mocked as required by the assignment. The server accepts both HTTP Basic credentials and JSON login payloads without validating them; do not use this as a real authentication service.

## Testing

```powershell
go test ./... -cover
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
go vet ./...
gofmt -l .
```

Run the official CSCE 3550 Gradebot client with the `project2` command against the running server. Keep the database file in the repository working directory, and include screenshots of Gradebot's rubric and test coverage with identifying information before submission.

## Security

Only public key values appear in JWKS. Private key material stays in the local SQLite database, which is excluded from Git. SQL query values are bound using `?` placeholders. The server is for coursework only and deliberately does not implement real credential verification.
