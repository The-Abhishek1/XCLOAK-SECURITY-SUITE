# Contributing to XCloak

First off — thank you. XCloak is a solo-maintained project and every
contribution matters.

---

## Ways to Contribute

- **Bug reports** — open an issue with the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml)
- **Feature requests** — open an issue with the [feature request template](.github/ISSUE_TEMPLATE/feature_request.yml)
- **Detection rules** — add Sigma rules to `xcloak-ngfw/backend/database/migrations/` (see below)
- **Code contributions** — pick up an open issue tagged `good first issue` or `help wanted`
- **Documentation** — fix typos, add examples, improve the deployment guide
- **Security vulnerabilities** — see [SECURITY.md](SECURITY.md) — do not open a public issue

---

## Development Setup

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.21+ | Backend + agent |
| Node.js | 18+ | Frontend (if you have access) |
| PostgreSQL | 16 | Primary database |
| Redis | 7+ | Rate limiting + sessions |
| Docker | 24+ | Observability stack |
| Flutter | 3.24.5 | Mobile agent |
| Java | 21 | Flutter Android toolchain |

### Backend

```bash
cd xcloak-ngfw/backend
cp .env.example .env
# Fill in DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, JWT_SECRET

# Start dependencies
docker compose up -d postgres redis

# Run with hot reload (install air: go install github.com/air-verse/air@latest)
air

# Or plain go run
go run ./main.go
```

### Go Agent

```bash
cd xcloak-agent
go build -o xcloak-agent ./main.go

# Run against your local backend
XCLOAK_SERVER=http://localhost:8080 ./xcloak-agent
```

### Mobile Agent

```bash
cd xcloak-agent-mobile
flutter pub get

# Connect an Android device or start an emulator
flutter run

# Build release APK
flutter build apk --release
```

---

## Code Guidelines

### Go (backend + agent)

- Use `log/slog` for all logging — never `fmt.Printf`/`fmt.Println`
- New service methods must call `services.LogEvent()` for any state-mutating operation
- Use `slog.Error` + named fields, never bare strings for errors
- Rate-limit any new public endpoint via `middleware.RateLimitAPI()`
- All new DB queries must go through the app pool (`database.AppPool`), not the migration pool
- New columns on tenant-scoped tables need a corresponding RLS policy review

### Dart / Flutter (mobile agent)

- All storage via `SecureStore` — never `SharedPreferences` for credentials
- Background service code lives in `background_worker.dart` — keep it lean
- New MDM commands go in `CommandService._execute()` — return a descriptive result string
- Every command must be acknowledged to the server (success or failure) — never silently drop

### Commit style

```
Type: short description (≤ 72 chars)

Optional body explaining WHY, not WHAT (the diff shows what).

Co-Authored-By: Your Name <you@example.com>
```

Types: `Feature`, `Fix`, `Harden`, `Docs`, `Refactor`, `Test`, `Chore`

---

## Adding a Sigma Rule

Detection rules live in the database seed migration. To add a rule:

1. Open `xcloak-ngfw/backend/database/migrations/000056_seed_sigma_rules.up.sql`
2. Add a row in the `INSERT INTO sigma_rules` block
3. Map to a MITRE ATT&CK technique if possible
4. Test by running the backend against a log that should match

Alternatively, add rules via the UI at **Detection → Sigma Rules → Import** — they will apply to your tenant immediately.

---

## Pull Request Process

1. Fork the repo and create a branch from `main`: `git checkout -b feature/my-thing`
2. Make your changes. If it touches the backend, run `go build ./...` to verify it compiles
3. If it touches the mobile agent, run `flutter analyze` and fix any warnings
4. Open a PR against `main` with the PR description template filled out
5. A maintainer will review within **5–7 business days** (solo project — thanks for your patience)
6. Squash merge is preferred for cleanliness

---

## Current Maintainer

**Abhishek N** — abhishekn1003@gmail.com

This is a solo-maintained project. Response times may vary. If you are interested in becoming a regular contributor or co-maintainer, reach out directly.
