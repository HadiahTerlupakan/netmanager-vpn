FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off: the SQLite driver is pure Go, and a static binary runs on alpine
# without matching libc versions.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/netmanager-vpn ./cmd/netmanager-vpn

FROM alpine:3.20
RUN apk add --no-cache nftables ca-certificates
COPY --from=build /out/netmanager-vpn /usr/local/bin/netmanager-vpn
# Runs as root on purpose: it creates WireGuard links and loads nftables rules
# in the host network namespace (hostNetwork / --network host), which needs
# NET_ADMIN, and file capabilities do not survive a non-root exec under every
# container runtime.
ENTRYPOINT ["/usr/local/bin/netmanager-vpn"]
