# Vault — Password Manager

A self-hosted password manager with end-to-end encryption, breach detection, and a minimal browser UI.

## Features

- **Zero-knowledge encryption** — passwords are encrypted client-side with AES-256-GCM before storage; the server never sees plaintext passwords
- **PBKDF2 key derivation** — master password is never stored; a 256-bit encryption key is derived on each request with 100 000 HMAC-SHA-256 iterations
- **Breach detection** — each password is checked against the [HaveIBeenPwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) k-anonymity API without sending the full hash
- **Duplicate detection** — warns when the same password is reused across multiple entries
- **JWT authentication** — stateless, token-based; tokens expire after 24 hours
- **Password generator** — cryptographically secure (`crypto.getRandomValues`) with configurable length and character sets

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Java 21 |
| Framework | Spring Boot 4.1 |
| Database | PostgreSQL 16 |
| Migrations | Flyway |
| Security | Spring Security + JJWT |
| Frontend | Vanilla JS + HTML/CSS (served as static resources) |
| Container | Docker + Docker Compose |
| CI | GitHub Actions |

## Security Model

```
Master Password
      │
      ▼
PBKDF2WithHmacSHA256 (100 000 iterations, 16-byte salt)
      │
      ├──► 256-bit verifier  →  stored in DB (password_hash)
      │
      └──► 256-bit AES key   →  used in memory only, never stored
                │
                ▼
         AES-256-GCM (random 96-bit IV per entry)
                │
                ▼
         encrypted_password + iv  →  stored in DB
```

The master password is sent once per request via `X-Master-Password` header (over HTTPS), used to re-derive the AES key, then discarded. The database stores only ciphertext.

## Getting Started

### Prerequisites

- Docker and Docker Compose
- A `.env` file in the project root (see below)

### Run with Docker Compose

```bash
git clone https://github.com/whflf/password-manager.git
cd password-manager
cp .env.example .env          # fill in JWT_SECRET
docker compose up --build -d
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | Yes | Base64-encoded secret for signing JWTs (min 32 bytes) |
| `DB_HOST` | No | Postgres host (default: `localhost`) |
| `DB_PORT` | No | Postgres port (default: `5432`) |
| `DB_NAME` | No | Database name (default: `vault`) |
| `DB_USER` | No | Database user (default: `postgres`) |
| `DB_PASSWORD` | No | Database password (default: `12345`) |

Generate a strong `JWT_SECRET`:

```bash
openssl rand -base64 32
```

### Run Locally (without Docker)

Requires Java 21 and a running PostgreSQL instance.

```bash
export JWT_SECRET=<your-secret>
export DB_HOST=localhost
./mvnw spring-boot:run
```

## API Reference

All vault endpoints require `Authorization: Bearer <token>` and `X-Master-Password: <password>` headers.

### Auth

| Method | Endpoint | Body | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | `{ email, masterPassword }` | Create account, returns JWT |
| `POST` | `/api/auth/login` | `{ email, masterPassword }` | Sign in, returns JWT |

### Vault

| Method | Endpoint | Body | Description |
|---|---|---|---|
| `GET` | `/api/vault` | — | List all entries (decrypted) |
| `POST` | `/api/vault` | `{ site, login, password }` | Create entry |
| `PUT` | `/api/vault/{id}` | `{ site, login, password }` | Update entry |
| `DELETE` | `/api/vault/{id}` | — | Delete entry |

**Example — register and add an entry:**

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","masterPassword":"correct-horse-battery"}' \
  | jq -r .token)

curl -X POST http://localhost:8080/api/vault \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Master-Password: correct-horse-battery" \
  -d '{"site":"github.com","login":"you@example.com","password":"hunter2"}'
```

**Response:**

```json
{
  "id": 1,
  "site": "github.com",
  "login": "you@example.com",
  "password": "hunter2",
  "pwned": true,
  "duplicate": false,
  "createdAt": "2026-07-22T18:51:56",
  "updatedAt": "2026-07-22T18:51:56"
}
```

## Running Tests

Unit tests require no external infrastructure:

```bash
./mvnw test
```

Integration tests (including `PasswordManagerApplicationTests`) require a running PostgreSQL instance and `JWT_SECRET` set in the environment. They are included in:

```bash
./mvnw verify
```

CI runs the full suite via GitHub Actions with a PostgreSQL service container on every push and pull request to `main`.

## Project Structure

```
src/
├── main/java/dev/whflf/vault/
│   ├── auth/          # Registration, login, JWT issuance
│   ├── crypto/        # AES-256-GCM encryptor, PBKDF2 key derivation
│   ├── vault/         # Entry CRUD, service, controller, DTOs
│   ├── audit/         # HaveIBeenPwned client, duplicate detection
│   └── security/      # JWT filter, Spring Security config
└── main/resources/
    ├── db/migration/  # Flyway SQL migrations
    └── static/        # Frontend (index.html, app.js)
```

## License

MIT
