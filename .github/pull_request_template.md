## What does this PR do?

<!-- One paragraph describing the change and why it's needed. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security fix
- [ ] Documentation
- [ ] Refactor / cleanup
- [ ] Chore (deps, CI, etc.)

## Checklist

- [ ] `go build ./...` passes (backend + agent)
- [ ] `flutter analyze` passes (if mobile agent changed)
- [ ] No `fmt.Printf` / `fmt.Println` — used `slog` instead
- [ ] New endpoints have `RequireAuth()` / `RequireRole()` middleware
- [ ] New state-mutating operations call `services.LogEvent()` for audit trail
- [ ] New DB queries go through `database.AppPool` (not migration pool)
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if user-facing

## Related issues

Closes #
