#!/bin/sh

cleanup() {
    rm -rf "$workdir"
    cleanup_docker >/dev/null 2>&1
}

cleanup_docker() {
    set +e
    docker container rm wgproxy hub spoke
    docker kill wgproxy hub spoke
    docker network rm wgproxy
    set -e
}

generate_keys() {
    prefix="$1"
    wg genkey >"$workdir"/"$prefix"-private-key
    wg pubkey <"$workdir"/"$prefix"-private-key >"$workdir"/"$prefix"-public-key
}

run_local() {
    sudo ip link delete wgtest 2>/dev/null || true
    sudo ip link add wgtest type wireguard
    sudo ip link set wgtest up
    sudo wg setconf wgtest "$workdir"/hub.conf
    ../target/debug/wgproxy "$workdir"/wgproxy.conf
    exit
}

wgclient() {
    docker run \
        --rm \
        --detach \
        --cap-add NET_ADMIN \
        --name "$1" \
        --volume "$workdir":/workdir \
        --network wgproxy \
        --ip "$2" \
        wgproxy/wireguard-client:latest \
        sh -c "
ip link add wgtest type wireguard
ip link set dev wgtest up
wg setconf wgtest /workdir/$1.conf
sleep infinity
" >/dev/null
}

run_docker() {
    cleanup_docker >/dev/null 2>&1
    sed -i 's/Endpoint = .*/Endpoint = 10.87.1.1:10000/' \
        "$workdir"/hub.conf \
        "$workdir"/spoke.conf
    cat "$workdir"/hub.conf
    cat "$workdir"/spoke.conf
    docker network create --subnet 10.87.0.0/16 wgproxy >/dev/null
    wgclient hub 10.87.2.1
    wgclient spoke 10.87.2.2
    docker run \
        --rm \
        -it \
        --name wgproxy \
        --volume "$workdir":/workdir \
        --volume "$PWD/..":/src \
        --network wgproxy \
        --ip 10.87.1.1 \
        docker.io/rust:latest \
        sh -c '
cd /src
cargo b
./target/debug/wgproxy /workdir/wgproxy.conf
'
}

set -ex
trap cleanup EXIT
workdir="$(mktemp -d)"
umask 0077
generate_keys wgproxy
generate_keys hub
generate_keys spoke
wg genpsk >"$workdir"/wgproxy-preshared-key
wg genpsk >"$workdir"/spoke-preshared-key
cat >"$workdir"/wgproxy.conf <<EOF
[Server]
PrivateKey = $(cat "$workdir"/wgproxy-private-key)
PresharedKey = $(cat "$workdir"/wgproxy-preshared-key)
ListenPort = 10000

[Hub]
PublicKey = $(cat "$workdir"/hub-public-key)

[Spoke]
PublicKey = $(cat "$workdir"/spoke-public-key)
EOF
cat >"$workdir"/hub.conf <<EOF
[Interface]
PrivateKey = $(cat "$workdir"/hub-private-key)

# authorize hub
[Peer]
Endpoint = 127.0.0.1:10000
PublicKey = $(cat "$workdir"/wgproxy-public-key)
PresharedKey = $(cat "$workdir"/wgproxy-preshared-key)
PersistentKeepalive = 23

[Peer]
PublicKey = $(cat "$workdir"/spoke-public-key)
PresharedKey = $(cat "$workdir"/spoke-preshared-key)
PersistentKeepalive = 23
EOF
cat >"$workdir"/spoke.conf <<EOF
[Interface]
PrivateKey = $(cat "$workdir"/spoke-private-key)

# authorize spoke
[Peer]
Endpoint = 127.0.0.1:10000
PublicKey = $(cat "$workdir"/wgproxy-public-key)
PresharedKey = $(cat "$workdir"/wgproxy-preshared-key)
PersistentKeepalive = 23

[Peer]
Endpoint = 127.0.0.1:10000
PublicKey = $(cat "$workdir"/hub-public-key)
PresharedKey = $(cat "$workdir"/spoke-preshared-key)
PersistentKeepalive = 23
EOF
#run_local
run_docker
