FROM golang:1.26-alpine3.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off: the SQLite driver is pure Go, and a static binary runs on alpine
# without matching libc versions.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/netmanager-vpn ./cmd/netmanager-vpn

FROM alpine:3.22
# iptables only reaches Docker's DOCKER-USER chain on hosts that run Docker;
# our own rules stay in nftables. strongSwan and accel-ppp carry L2TP/IPsec;
# the hub starts them only when the host exposes /dev/ppp and l2tp_ppp.
RUN apk add --no-cache nftables iptables ca-certificates strongswan accel-ppp
COPY --from=build /out/netmanager-vpn /usr/local/bin/netmanager-vpn
# Runs as root on purpose: it creates WireGuard links and loads nftables rules
# in the host network namespace (hostNetwork / --network host), which needs
# NET_ADMIN, and file capabilities do not survive a non-root exec under every
# container runtime.
ENTRYPOINT ["/usr/local/bin/netmanager-vpn"]
