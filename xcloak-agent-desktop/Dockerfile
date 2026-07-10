FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "-s -w -X main.Version=${VERSION}" \
    -o xcloak-agent-desktop ./main.go

# Distroless static includes CA certs but nothing else — keeps the image minimal.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /src/xcloak-agent-desktop /xcloak-agent-desktop

# eBPF requires elevated privileges at runtime; grant them via --privileged
# or the specific caps: CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN.
ENTRYPOINT ["/xcloak-agent-desktop"]
