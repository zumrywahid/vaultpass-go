# VaultPass Go Backend

A high-performance, zero-knowledge password manager backend built in Go. The server acts as an encrypted storage relay — it never has access to plaintext passwords, encryption keys, or vault contents. All cryptographic operations happen client-side; the backend stores and syncs only opaque encrypted blobs.

Part of the [VaultPass](#related-repositories) ecosystem: native iOS, Android, and web clients that share the same E2E encryption protocol.

## Table of Contents

- [Architecture](#architecture)
- [Security Model](#security-model)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Sync Protocol](#sync-protocol)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Running Tests](#running-tests)
- [Client Integration](#client-integration)
- [Related Repositories](#related-repositories)
- [Author](#author)
- [License](#license)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Client Apps                         │
│           (iOS / Android / Web Dashboard)                │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Master Pass  │  │  AES-256-GCM │  │  Argon2id    │   │
│  │  + Biometric │  │  Encryption  │  │  Key Derive  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │            │
│         │     Encrypted Blob (opaque)       │            │
└─────────┼─────────────────┼─────────────────┼────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────┐
│                   Go Backend (this repo)                 │
│                                                          │
│  ┌─────────┐  ┌─────────────┐  ┌──────────────────────┐ │
│  │  Auth   │  │    Vault    │  │   Password Generator │ │
│  │ Service │  │  Sync Engine│  │      (crypto/rand)   │ │
│  └────┬────┘  └──────┬──────┘  └──────────────────────┘ │
│       │              │                                   │
│  ┌────┴──────────────┴────────────────────────────────┐  │
│  │               MySQL (encrypted blobs only)         │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**Key principle:** The server is intentionally "dumb." It authenticates users, stores encrypted blobs, and resolves sync conflicts — but it never decrypts, inspects, or processes vault contents. This is the foundation of the zero-knowledge architecture.

## Security Model

### Zero-Knowledge Architecture

| Layer | What the Server Knows | What the Server Never Sees |
|-------|----------------------|---------------------------|
| **Authentication** | Argon2id hash of the auth key | Master password, encryption key |
| **Vault Storage** | Encrypted blob size, timestamps | Passwords, URLs, usernames, notes |
| **Sync** | Entry UUIDs, version numbers | Decrypted entry contents |

### Cryptographic Primitives

| Purpose | Algorithm | Implementation |
|---------|-----------|----------------|
| Password hashing | **Argon2id** | 64 MB memory, 3 iterations, 2 parallelism, 16-byte salt, 32-byte key |
| Hash encoding | **PHC string format** | `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>` |
| Password comparison | **Constant-time** | `crypto/subtle.ConstantTimeCompare` to prevent timing attacks |
| Token signing | **HMAC-SHA256 (JWT)** | Scoped with issuer (`vaultpass`) and audience (`vaultpass-api`) claims |
| Password generation | **crypto/rand** | CSPRNG with Fisher-Yates shuffle — never `math/rand` |
| Random salt generation | **crypto/rand** | 16-byte random salt per password hash |

### Security Hardening

- **Request body limits** — `http.MaxBytesReader` on all endpoints (1 MB auth, 10 MB vault) to prevent OOM attacks
- **Per-IP rate limiting** — Token bucket rate limiter on authentication endpoints (5 req/s, burst 10) with automatic stale entry cleanup
- **Sync entry limit** — Maximum 1,000 entries per sync request to prevent database exhaustion
- **Input validation** — Entry ID format validation (UUID, max 36 chars) at system boundaries
- **Graceful degradation** — Server starts without database (health check and password generator remain available)
- **Production safety** — Fatal exit if JWT secret is left as default in production environment
- **Soft deletes** — Vault entries are soft-deleted with version increment to propagate through sync

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **Language** | Go 1.24 | High performance, strong concurrency, excellent standard library |
| **Router** | [chi](https://github.com/go-chi/chi) v5 | Lightweight, idiomatic, composable middleware |
| **Database** | MySQL | Reliable, ACID-compliant, handles encrypted blob storage well |
| **Key Derivation** | [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) | OWASP-recommended KDF, memory-hard to resist GPU attacks |
| **JWT** | [golang-jwt](https://github.com/golang-jwt/jwt) v5 | Industry-standard token authentication |
| **Rate Limiting** | [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) | Official Go rate limiter with token bucket algorithm |
| **Config** | [godotenv](https://github.com/joho/godotenv) | Simple `.env` file loading for local development |
| **Logging** | `log/slog` (stdlib) | Structured logging built into Go standard library |

## Project Structure

```
vaultpass-go/
├── cmd/
│   └── api/
│       └── main.go                 # Application entrypoint, router setup, graceful shutdown
│
├── internal/                       # Private application packages (Go convention)
│   ├── config/
│   │   └── config.go               # Environment-based configuration with production safety checks
│   │
│   ├── crypto/                     # Cryptographic operations
│   │   ├── generator.go            # CSPRNG password generator with configurable rules
│   │   ├── generator_test.go       # Table-driven tests (11 cases) + uniqueness verification
│   │   ├── hash.go                 # Argon2id hashing with PHC string format encoding
│   │   ├── hash_test.go            # Hash/verify tests + salt uniqueness validation
│   │   ├── jwt.go                  # JWT generation & validation with issuer/audience scoping
│   │   └── jwt_test.go             # Token lifecycle tests including expiry and claim validation
│   │
│   ├── handler/                    # HTTP request handlers (transport layer)
│   │   ├── auth.go                 # POST /register, POST /login, GET /me
│   │   ├── generator.go            # POST /generate + shared JSON response helpers
│   │   └── vault.go                # CRUD + sync endpoints with body size limits
│   │
│   ├── middleware/                  # HTTP middleware chain
│   │   ├── auth.go                 # JWT Bearer token extraction and context injection
│   │   ├── logging.go              # Structured request logging (method, path, duration)
│   │   └── ratelimit.go            # Per-IP token bucket rate limiter with background cleanup
│   │
│   ├── model/                      # Domain models and DTOs
│   │   ├── generator.go            # GenerateRequest / GenerateResponse
│   │   ├── user.go                 # User, CreateUserRequest, LoginRequest, AuthResponse
│   │   └── vault.go                # VaultEntry, VaultEntryRequest, SyncRequest, SyncResponse
│   │
│   ├── repository/                 # Data access layer (MySQL)
│   │   ├── db.go                   # Connection pool setup (25 open, 5 idle, 5min lifetime)
│   │   ├── user.go                 # User CRUD with duplicate detection
│   │   ├── user_test.go            # Repository initialization and error sentinel tests
│   │   └── vault.go                # Vault CRUD + upsert with LWW conflict resolution
│   │
│   └── service/                    # Business logic layer
│       ├── auth.go                 # Registration, login, token issuance
│       ├── auth_test.go            # Input validation tests
│       ├── generator.go            # Password generation with default handling
│       ├── generator_test.go       # Generation option mapping tests
│       ├── vault.go                # Vault CRUD + delta sync with transaction support
│       └── vault_test.go           # Validation, base64 encoding, and empty slice tests
│
├── migrations/
│   ├── 001_create_users_table.sql  # Users table with email uniqueness
│   └── 002_create_vault_entries.sql # Vault entries with composite indexes and FK cascade
│
├── .env.example                    # Environment variable template
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

### Layered Architecture

```
HTTP Request
    │
    ▼
┌──────────┐     Validates tokens, limits request size, logs requests
│Middleware │     auth.go, ratelimit.go, logging.go
└────┬─────┘
     ▼
┌──────────┐     Parses JSON, maps HTTP status codes, routes requests
│ Handler  │     auth.go, vault.go, generator.go
└────┬─────┘
     ▼
┌──────────┐     Business rules, validation, orchestrates operations
│ Service  │     auth.go, vault.go, generator.go
└────┬─────┘
     ▼
┌──────────┐     SQL queries, connection pooling, error mapping
│Repository│     user.go, vault.go, db.go
└────┬─────┘
     ▼
   MySQL
```

Each layer only communicates with the layer directly below it. The `internal/` package boundary enforces this at the compiler level — external packages cannot import these modules.

## API Reference

### Public Endpoints

#### Health Check

```
GET /health
```

Returns `ok` if the server is running. Available even without database connectivity.

#### Password Generator

```
POST /api/v1/generate
Content-Type: application/json

{
  "length": 24,
  "uppercase": true,
  "lowercase": true,
  "numbers": true,
  "symbols": false
}
```

```json
{
  "password": "kR7mNxB2pQ9wYjL4vT8hCs",
  "length": 24
}
```

All fields are optional. Defaults: length 16, all character types enabled. Length range: 8-128. Uses `crypto/rand` exclusively for cryptographically secure generation.

### Authentication Endpoints

Rate limited: 5 requests/second per IP, burst 10.

#### Register

```
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your-auth-key"
}
```

```json
// 201 Created
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "created_at": "2026-02-23T12:00:00Z"
  }
}
```

| Status | Reason |
|--------|--------|
| 201 | Account created |
| 400 | Missing email or password |
| 409 | Email already registered |
| 413 | Request body too large |
| 429 | Rate limit exceeded |

#### Login

```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your-auth-key"
}
```

```json
// 200 OK
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "created_at": "2026-02-23T12:00:00Z"
  }
}
```

| Status | Reason |
|--------|--------|
| 200 | Login successful |
| 401 | Invalid credentials |
| 429 | Rate limit exceeded |

### Protected Endpoints

All require `Authorization: Bearer <token>` header.

#### Get Current User

```
GET /api/v1/auth/me
Authorization: Bearer <token>
```

```json
{
  "id": 1,
  "email": "user@example.com",
  "created_at": "2026-02-23T12:00:00Z"
}
```

#### Create Vault Entry

```
POST /api/v1/vault
Authorization: Bearer <token>
Content-Type: application/json

{
  "entry_id": "550e8400-e29b-41d4-a716-446655440000",
  "encrypted_data": "base64-encoded-encrypted-blob"
}
```

```json
// 201 Created
{
  "entry_id": "550e8400-e29b-41d4-a716-446655440000",
  "encrypted_data": "base64-encoded-encrypted-blob",
  "version": 1,
  "updated_at": "2026-02-23T12:00:00Z",
  "deleted": false
}
```

The `entry_id` is a client-generated UUID. The `encrypted_data` is a base64-encoded blob — the server stores it as-is without inspection.

#### List Vault Entries

```
GET /api/v1/vault
Authorization: Bearer <token>
```

```json
[
  {
    "entry_id": "550e8400-e29b-41d4-a716-446655440000",
    "encrypted_data": "base64-encoded-encrypted-blob",
    "version": 2,
    "updated_at": "2026-02-23T12:00:00Z",
    "deleted": false
  }
]
```

Returns all non-deleted entries for the authenticated user. Returns `[]` (empty array, never `null`) if no entries exist.

#### Update Vault Entry

```
PUT /api/v1/vault/{entry_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "encrypted_data": "updated-base64-encoded-blob"
}
```

Increments the entry version automatically. Returns 404 if the entry doesn't exist.

#### Delete Vault Entry

```
DELETE /api/v1/vault/{entry_id}
Authorization: Bearer <token>
```

Returns `204 No Content`. Performs a soft delete (sets `deleted = true` and increments version) so the deletion propagates through sync.

#### Sync Vault

```
POST /api/v1/vault/sync
Authorization: Bearer <token>
Content-Type: application/json

{
  "last_synced_at": "2026-02-23T12:00:00Z",
  "entries": [
    {
      "entry_id": "uuid-1",
      "encrypted_data": "base64-blob",
      "version": 3,
      "deleted": false
    }
  ]
}
```

```json
{
  "synced_at": "2026-02-23T12:05:00Z",
  "entries": [
    {
      "entry_id": "uuid-2",
      "encrypted_data": "base64-blob",
      "version": 1,
      "updated_at": "2026-02-23T12:03:00Z",
      "deleted": false
    }
  ],
  "skipped": 0
}
```

Set `last_synced_at` to `null` for a full sync (first-time sync). Use the returned `synced_at` as `last_synced_at` in subsequent requests. Maximum 1,000 entries per request.

## Database Schema

### users

```sql
CREATE TABLE users (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    email      VARCHAR(255) UNIQUE NOT NULL,
    auth_hash  VARCHAR(255) NOT NULL,           -- Argon2id hash (PHC format)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### vault_entries

```sql
CREATE TABLE vault_entries (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id        BIGINT NOT NULL,
    entry_id       VARCHAR(36) NOT NULL,          -- Client-generated UUID
    encrypted_data MEDIUMBLOB NOT NULL,            -- Opaque encrypted blob (up to 16 MB)
    version        INT NOT NULL DEFAULT 1,         -- Monotonic version for conflict resolution
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted        BOOLEAN NOT NULL DEFAULT FALSE, -- Soft delete for sync propagation

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_user_entry (user_id, entry_id),
    INDEX idx_user_updated (user_id, updated_at),
    INDEX idx_user_deleted (user_id, deleted)
);
```

**Index strategy:**
- `idx_user_entry` — Enforces one entry per UUID per user; used by upsert operations
- `idx_user_updated` — Supports delta sync queries (`WHERE updated_at > ?`)
- `idx_user_deleted` — Supports listing non-deleted entries

## Sync Protocol

The sync engine implements **delta sync with Last-Write-Wins (LWW) conflict resolution** based on monotonically increasing version numbers.

### How It Works

```
  Client A                    Server                     Client B
     │                          │                           │
     │  1. Edit entry locally   │                           │
     │  (version 1 → 2)        │                           │
     │                          │                           │
     │  2. POST /vault/sync ──► │                           │
     │  {entries: [{v:2}],      │                           │
     │   last_synced: t1}       │                           │
     │                          │  3. Upsert: v2 > v1? Yes  │
     │                          │     → Accept update       │
     │                          │                           │
     │  ◄── 4. Response ─────── │                           │
     │  {synced_at: t2,         │                           │
     │   entries: [changes]}    │                           │
     │                          │                           │
     │                          │  5. POST /vault/sync ◄─── │
     │                          │  {last_synced: t0}        │
     │                          │                           │
     │                          │ ──► 6. Response ────────► │
     │                          │  {entries: [{v:2}]}       │
     │                          │  (Client B gets update)   │
```

### Conflict Resolution

When two clients edit the same entry offline:

```
Client A: entry "abc" version 2 → 3 (edited title)
Client B: entry "abc" version 2 → 3 (edited password)

Client A syncs first  → Server accepts v3
Client B syncs second → Server compares: v3 > v3? No → Rejects (keeps A's version)
                        Server returns A's v3 to Client B in response
```

The server uses `INSERT ... ON DUPLICATE KEY UPDATE` with a version guard:

```sql
UPDATE encrypted_data = IF(incoming_version > current_version, incoming_data, current_data)
```

This is atomic at the database level — no race conditions.

### Sync Lifecycle

| Scenario | `last_synced_at` | Server Behavior |
|----------|-----------------|-----------------|
| First sync ever | `null` | Returns ALL entries (full sync) |
| Subsequent sync | Previous `synced_at` value | Returns only entries changed since that timestamp |
| Offline edits | Stale timestamp | Client sends local changes + gets all missed server changes |
| Delete propagation | Any | Deleted entries included in sync response with `deleted: true` |

### Transaction Safety

All incoming entries in a single sync request are processed within a database transaction. If any entry fails, the entire batch is rolled back — no partial sync states.

## Getting Started

### Prerequisites

- Go 1.22+
- MySQL 8.0+

### Setup

```bash
# Clone the repository
git clone https://github.com/zumrywahid/vaultpass-go.git
cd vaultpass-go

# Install dependencies
go mod download

# Create the database
mysql -u root -p -e "CREATE DATABASE vaultpass;"

# Run migrations
mysql -u root -p vaultpass < migrations/001_create_users_table.sql
mysql -u root -p vaultpass < migrations/002_create_vault_entries.sql

# Configure environment
cp .env.example .env
# Edit .env with your MySQL credentials

# Run the server
go run cmd/api/main.go
```

The server starts on `http://localhost:8080` by default.

### Quick Test

```bash
# Health check
curl http://localhost:8080/health

# Generate a password
curl -s -X POST http://localhost:8080/api/v1/generate \
  -H "Content-Type: application/json" \
  -d '{"length": 24, "symbols": true}' | jq

# Register
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "securepassword"}' | jq

# Login and save token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "securepassword"}' | jq -r '.token')

# Create a vault entry
curl -s -X POST http://localhost:8080/api/v1/vault \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"entry_id": "550e8400-e29b-41d4-a716-446655440000", "encrypted_data": "dGVzdC1lbmNyeXB0ZWQtZGF0YQ=="}' | jq

# List vault entries
curl -s http://localhost:8080/api/v1/vault \
  -H "Authorization: Bearer $TOKEN" | jq

# Sync
curl -s -X POST http://localhost:8080/api/v1/vault/sync \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"entries": []}' | jq
```

## Configuration

All configuration is via environment variables (loaded from `.env` in development).

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `ENV` | `development` | Environment (`development` or `production`) |
| `DATABASE_DSN` | `root:password@tcp(127.0.0.1:3306)/vaultpass?parseTime=true` | MySQL connection string |
| `JWT_SECRET` | `dev-secret-change-in-production` | HMAC signing key for JWT tokens |

**Production notes:**
- `JWT_SECRET` **must** be set to a strong random value. The server will refuse to start in `production` mode with the default secret.
- Use a minimum 32-character random string for `JWT_SECRET`.
- Ensure `DATABASE_DSN` uses a dedicated database user with minimal privileges.

## Running Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run specific package tests
go test ./internal/crypto/... -v     # Cryptographic tests
go test ./internal/service/... -v    # Business logic tests
go test ./internal/repository/... -v # Repository tests

# Run with race detection
go test -race ./...

# Run with coverage
go test -cover ./...
```

### Test Coverage

| Package | Tests | Coverage Focus |
|---------|-------|----------------|
| `crypto` | 17 | Password generation, Argon2id hash/verify, JWT lifecycle, claim validation |
| `service` | 12 | Input validation, base64 encoding roundtrip, default handling, empty state |
| `repository` | 3 | Initialization, error sentinels, duplicate detection |

## Client Integration

This backend serves as the sync layer for native VaultPass clients. Each client is a standalone app that works fully offline — the backend is only needed for cross-device sync.

```
┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│   VaultPass iOS      │     │  VaultPass Android    │     │  VaultPass Web       │
│   Swift / SwiftUI    │     │  Kotlin / Compose     │     │  Next.js             │
│                      │     │                       │     │                      │
│  ┌────────────────┐  │     │  ┌─────────────────┐  │     │  ┌────────────────┐  │
│  │ Keychain       │  │     │  │ Android Keystore│  │     │  │ WebCrypto API  │  │
│  │ FaceID/TouchID │  │     │  │ BiometricPrompt │  │     │  │                │  │
│  │ AES-256-GCM    │  │     │  │ AES-256-GCM     │  │     │  │ AES-256-GCM    │  │
│  │ Argon2id       │  │     │  │ Argon2id        │  │     │  │ Argon2id       │  │
│  └───────┬────────┘  │     │  └────────┬────────┘  │     │  └───────┬────────┘  │
│          │           │     │           │            │     │          │           │
│  Encrypt locally     │     │  Encrypt locally      │     │  Encrypt locally     │
│  before sending      │     │  before sending       │     │  before sending      │
└──────────┬───────────┘     └───────────┬────────────┘     └──────────┬───────────┘
           │                             │                             │
           │    Encrypted blobs only     │     Encrypted blobs only    │
           │    (HTTPS + JWT auth)       │     (HTTPS + JWT auth)      │
           ▼                             ▼                             ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                        VaultPass Go Backend (this repo)                          │
│                                                                                  │
│   /api/v1/auth/register    Register with email + auth key (Argon2id hashed)      │
│   /api/v1/auth/login       Authenticate and receive JWT                          │
│   /api/v1/vault/sync       Delta sync — send local changes, receive remote       │
│   /api/v1/vault            CRUD encrypted vault entries                           │
│   /api/v1/generate         Server-side CSPRNG password generation                │
│                                                                                  │
│   The server NEVER sees plaintext passwords, URLs, usernames, or notes.          │
│   All vault data arrives pre-encrypted. The server stores and syncs opaque       │
│   blobs using LWW conflict resolution with monotonic version numbers.            │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### How Clients Use This Backend

1. **Registration/Login** — Client derives an auth key from the master password using Argon2id and sends it to `/api/v1/auth/register` or `/login`. The server hashes this auth key again with Argon2id before storing it.

2. **Vault Encryption** — All encryption happens on the client. Each vault entry is encrypted with AES-256-GCM using a key derived from the master password. The server only stores the resulting opaque base64-encoded blobs.

3. **Sync** — Clients call `POST /api/v1/vault/sync` with their local changes and `last_synced_at` timestamp. The server responds with any remote changes since that timestamp. Conflicts are resolved by highest version number (Last-Write-Wins).

4. **Offline-First** — Clients maintain a complete local vault (SQLite/Room on Android, SwiftData on iOS). The backend is optional — the app is fully functional without network access.

## Related Repositories

VaultPass is built natively for each platform — not cross-compiled. Each client implements the same E2E encryption protocol and syncs through this Go backend.

| Repository | Stack | Description |
|------------|-------|-------------|
| [**vaultpass-go**](https://github.com/zumrywahid/vaultpass-go) (this repo) | Go | Backend API — zero-knowledge sync service |
| [**vaultpass-ios**](https://github.com/zumrywahid/vaultpass-ios) | Swift / SwiftUI | iOS client — Keychain, FaceID, AutoFill |
| [**vaultpass-android**](https://github.com/zumrywahid/vaultpass-android) | Kotlin / Jetpack Compose | Android client — Keystore, Biometrics, Autofill |
| **vaultpass-nextjs** | Next.js | Web dashboard — WebCrypto API (coming soon) |

## Author

**Zumry Wahid** — [github.com/zumrywahid](https://github.com/zumrywahid)

VaultPass is a portfolio project demonstrating native platform mastery, security/crypto domain knowledge, and Go backend development. Each platform — iOS, Android, and web — is built natively to showcase deep OS integration rather than cross-platform abstraction.

## License

MIT
