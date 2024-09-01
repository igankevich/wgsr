WGX is an authenticated and end-to-end encrypted Wireguard relay for hub-and-spoke networks.
- It allows two Wireugard peers residing in different local-area networks to communicate.
- It is compatible with all standard Wireguard implementations (Linux, Android, iOS, MacOS, Windows etc.).
- Relay authenticates every peer to prevent even a single foreign packet reach your local-area networks.
- Relay passes all the packets through without decrypting them (this is in contrast to a regular Wireguard peer that re-encrypts all the packets passed through it).

The goal of the project is to implement efficient NAT traversal for standard Wireguard implementations without patching them.
Currently it works for hub-and-spoke networks, and all packets go over a relay.
Future work is to send packets directly wherever possible.


# How it works?

The relay itself is a Wireguard peer that you add to your Wireguard configuration as any other peer.
Once added the peers perform regular handshakes with the relay thus «punching a hole» in NAT.
Then in your _spoke_ peer you replace hub's endpoint with the relay's endpoint,
and the packets will go back and forth through the punched hole.

_Hub_ peer needs to tell the relay which public keys it wants to communicate with.
This is done by sending a configuration command over the established Wireguard tunnel directly to the relay.
These commands are sent as UDP packets.

After that the handshake between _hub_ and _spoke_ will succeed and you can use your Wireguard network as usual.

To summarize:
- add the relay as a peer to your _hub_ and _spoke_ Wireguard configuration (`wgx export`),
- replace hub's endpoint with relay's endpoint in the _spoke_ Wireguard configuration,
- tell the relay which peers the hub wants to communicate with (`wgx-hub join`).


# Installation


## Relay

Run these commands on the server with a public IP.

```bash
# generate the configuration file
umask 077
cat >/etc/wgx.conf <<EOF
[Relay]
PrivateKey = $(wg genkey)
AllowedPublicKeys = # comma-separated list of hub's and spokes' public keys
EOF

# run the relay in the background
docker run \
    --rm \
    --name wgx \
    --volume /etc/wgx.conf:/etc/wgx.conf \
    --network host \
    --restart always \
    --detach \
    docker.io/igankevich/wgx:latest \
    /bin/wgxd /etc/wgx.conf

# alias wgx command-line client
alias wgx='docker exec wgx /bin/wgx'

# print status
wgx status

# print active sessions
wgx sessions
```


## Hub

Run this command on the hub (a Wireguard peer to which every other peer is connected).

```bash
# configure relay
docker run \
    -it \
    --rm \
    --network host \
    docker.io/igankevich/wgx:latest \
    /bin/wgx-hub join wg0 RELAY-IP
# here wg0 - wireguard interface name
# RELAY-IP  - public ip address of the relay
```

The command will configure the relay as a peer, and
then send the public keys of all the other peers to the relay for routing.
