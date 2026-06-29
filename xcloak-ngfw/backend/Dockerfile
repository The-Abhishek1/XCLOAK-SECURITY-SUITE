# Backend has no os/exec calls and migrations are compiled in via
# //go:embed (database/migrate.go), so the runtime image needs nothing but
# the static binary — no shell, no filesystem access to source.
FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/xcloak-backend .

FROM alpine:3.19
WORKDIR /app
RUN addgroup -g 1001 -S appgroup && adduser -S -u 1001 -G appgroup appuser
COPY --from=builder /out/xcloak-backend /app/xcloak-backend

EXPOSE 8080 8443
USER appuser
ENTRYPOINT ["/app/xcloak-backend"]
