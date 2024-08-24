#!/bin/sh

cleanup() {
    rm -rf "$workdir"
}

set -e
workdir="$(mktemp -d)"
cat >"$workdir"/wg.conf <<EOF
[Interface]
PrivateKey = $(wg genkey)

# wgx authentication peer
[Peer]
PublicKey = 4F4vVu4k40zx8cSx/ApqGobap+kzTXTmGWGW8hf2Hjg=
Endpoint = 159.69.148.189:1622
# Endpoint = [2a01:4f8:1c1b:5ea5::1]:1622
PersistentKeepalive = 23
AllowedIPs = 10.87.87.87/32
EOF
sudo ip link delete wgtest 2>/dev/null || true
sudo ip link add wgtest type wireguard
sudo ip link set wgtest up
sudo wg setconf wgtest "$workdir"/wg.conf
sudo ip address add 10.87.87.1/32 dev wgtest
sudo ip route add 10.87.0.0/16 dev wgtest
