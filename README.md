WGX is an authenticated and end-to-end encrypted Wireguard relay for hub-and-spoke networks.
- It allows two Wireugard peers residing in different local-area networks to communicate.
- It is compatible with all standard Wireguard implementations (Linux, Android, iOS, MacOS, Windows etc.).
- Relay authenticates every peer to prevent even a single foreign packet reach your local-area networks.
- Relay passes all the packets through without decrypting them (this is in contrast to a regular Wireguard peer that re-encrypts all the packets passed through it).

The goal of the project is to implement efficient NAT traversal for standard Wireguard implementations without patching them.
Currently it works for hub-and-spoke networks and all packets go over a relay.
Future work is to send packets directly wherever possible.


# How it works?
