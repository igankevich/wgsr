use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::mem::take;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::SystemTime;

use log::error;
use log::trace;
use mio::net::UdpSocket;
use mio::{Interest, Poll, Token};
use rand::Rng;
use rand_core::OsRng;
use wgproto::DecodeWithContext;
use wgproto::EncodeWithContext;
use wgproto::EncryptedHandshakeInitiation;
use wgproto::EncryptedHandshakeResponse;
use wgproto::EncryptedPacketData;
use wgproto::InputBuffer;
use wgproto::MacSigner;
use wgproto::MacVerifier;
use wgproto::Message;
use wgproto::MessageKind;
use wgproto::MessageVerifier;
use wgproto::PresharedKey;
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgproto::Responder;
use wgproto::Session;
use wgproto::SessionIndex;
use wgx::AllowedPublicKeys;
use wgx::MessageKindExt;
use wgx::Routes;
use wgx::RpcDecode;
use wgx::RpcEncode;
use wgx::RpcRequest;
use wgx::RpcRequestBody;
use wgx::RpcResponse;
use wgx::RpcResponseBody;
use wgx::Sessions;
use wgx::Status;
use wgx::ToBase64;

use crate::format_error;
use crate::get_internet_addresses;
use crate::Config;
use crate::Error;
use crate::IpPacket;
use crate::IpPacketView;

pub(crate) struct WireguardRelay {
    socket: UdpSocket,
    private_key: PrivateKey,
    preshared_key: PresharedKey,
    public_key: PublicKey,
    auth_peers: HashMap<PublicKey, AuthPeer>,
    hub_to_spokes: HashMap<PublicKey, HashSet<PublicKey>>,
    spoke_to_hub: HashMap<PublicKey, PublicKey>,
    allowed_public_keys: AllowedPublicKeys,
    socket_addr_to_public_key: HashMap<SocketAddr, PublicKey>,
    // (sender-socket-address, receiver-index) -> receiver-public-key
    // (receiver-socket-address, sender-index) -> sender-public-key
    sessions: HashMap<(SocketAddr, u32), PublicKey>,
    events: BinaryHeap<ExpiryEvent>,
    buffer: Vec<u8>,
}

impl WireguardRelay {
    pub(crate) fn new(config: Config, server_token: Token, poll: &mut Poll) -> Result<Self, Error> {
        let socket_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), config.listen_port.into());
        let mut socket = UdpSocket::bind(socket_addr)?;
        poll.registry()
            .register(&mut socket, server_token, Interest::READABLE)?;
        Ok(Self {
            socket,
            public_key: (&config.private_key).into(),
            private_key: config.private_key,
            preshared_key: [0_u8; 32].into(),
            auth_peers: Default::default(),
            hub_to_spokes: Default::default(),
            spoke_to_hub: Default::default(),
            allowed_public_keys: config.allowed_public_keys,
            socket_addr_to_public_key: Default::default(),
            sessions: Default::default(),
            events: Default::default(),
            buffer: vec![0_u8; MAX_PACKET_SIZE],
        })
    }

    pub(crate) fn on_event(&mut self) -> Result<(), Error> {
        loop {
            let (n, from) = match self.socket.recv_from(&mut self.buffer) {
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // no more packets
                    return Ok(());
                }
                other => other,
            }?;
            let buffer = take(&mut self.buffer);
            let packet = &buffer[..n];
            let ret = self.on_packet(packet, from);
            self.buffer = buffer;
            if let Err(e) = ret {
                error!("wg-relay error: {}", e);
            }
        }
    }

    fn on_packet(&mut self, packet: &[u8], from: SocketAddr) -> Result<(), Error> {
        let mut buffer = InputBuffer::new(packet);
        let mut context = MacVerifier::new(&self.public_key, None);
        context.check_macs = false;
        if buffer.get(0) == Some(&(MessageKindExt::GetPublicKey as u8)) {
            self.socket.send_to(self.public_key.as_bytes(), from)?;
            return Ok(());
        }
        let message = Message::decode_with_context(&mut buffer, &mut context)?;
        match message {
            Message::HandshakeInitiation(message) => {
                context.check_macs = true;
                match context.verify(&mut buffer) {
                    Ok(_) => self.on_handshake_initiation(message, from, packet)?,
                    Err(_) => self.on_other_handshake_initiation(message, from, packet)?,
                }
            }
            Message::HandshakeResponse(message) => {
                self.on_handshake_response(message, from, packet)?
            }
            Message::PacketData(message) => self.on_packet_data(message, from, packet)?,
        }
        Ok(())
    }

    fn on_handshake_initiation(
        &mut self,
        message: EncryptedHandshakeInitiation,
        from: SocketAddr,
        packet: &[u8],
    ) -> Result<(), Error> {
        let (session, initiation, response_bytes) = Responder::respond(
            self.public_key,
            self.private_key.clone(),
            &self.preshared_key,
            message,
        )?;
        if let AllowedPublicKeys::Set(allowed_public_keys) = &self.allowed_public_keys {
            if !allowed_public_keys.contains(&initiation.static_public) {
                return Err(format_error!(
                    "untrusted public key: `{}`",
                    initiation.static_public.to_base64()
                ));
            }
        }
        trace!(
            "{}->wgx auth-peer->wgx {:?}",
            from,
            MessageKind::HandshakeInitiation
        );
        self.socket.send_to(response_bytes.as_slice(), from)?;
        trace!(
            "wgx->{} wgx->auth-peer {:?}",
            from,
            MessageKind::HandshakeResponse
        );
        self.socket_addr_to_public_key
            .insert(from, initiation.static_public);
        // sender and receiver are flipped here
        self.sessions
            .insert((from, session.sender_index().as_u32()), self.public_key);
        use std::collections::hash_map::Entry;
        let new_auth_peer = AuthPeer {
            session,
            socket_addr: from,
            created_at: SystemTime::now(),
            bytes_received: packet.len() as u64,
            bytes_sent: response_bytes.len() as u64,
        };
        self.events.push(ExpiryEvent {
            expiry: new_auth_peer.expiry(),
            public_key: initiation.static_public,
            session_index: new_auth_peer.session.sender_index(),
        });
        match self.auth_peers.entry(initiation.static_public) {
            Entry::Vacant(v) => {
                v.insert(new_auth_peer);
            }
            Entry::Occupied(mut o) => {
                let old_from = o.get().socket_addr;
                self.sessions
                    .remove(&(old_from, o.get().session.sender_index().as_u32()));
                let mut new_auth_peer = new_auth_peer;
                new_auth_peer.bytes_received = o.get().bytes_received;
                new_auth_peer.bytes_sent = o.get().bytes_sent;
                *o.get_mut() = new_auth_peer;
            }
        }
        Ok(())
    }

    fn on_other_handshake_initiation(
        &mut self,
        message: EncryptedHandshakeInitiation,
        from: SocketAddr,
        packet: &[u8],
    ) -> Result<(), Error> {
        let kind = MessageKind::HandshakeInitiation;
        let from_public_key = self
            .socket_addr_to_public_key
            .get(&from)
            .ok_or_else(|| format_error!("no route for {:?} from {}", kind, from))?;
        if self.hub_to_spokes.contains_key(from_public_key) {
            return Err(format_error!(
                "handshake from `{}` failed verification",
                from_public_key.to_base64()
            ));
        }
        let to_public_key = self
            .spoke_to_hub
            .get(from_public_key)
            .ok_or_else(|| format_error!("no route for {:?} from {}", kind, from))?;
        let to_socket_addr = self
            .auth_peers
            .get(to_public_key)
            .ok_or_else(|| {
                format_error!(
                    "no route for {:?} from {}: peer not unauthorized",
                    kind,
                    from
                )
            })?
            .socket_addr;
        trace!("{}->{} spoke->hub {:?}", from, to_socket_addr, kind);
        self.socket.send_to(packet, to_socket_addr)?;
        // sender and receiver are flipped here
        self.sessions.insert(
            (to_socket_addr, message.sender_index.as_u32()),
            *from_public_key,
        );
        let nbytes = packet.len() as u64;
        if let Some(peer) = self.auth_peers.get_mut(from_public_key) {
            peer.bytes_received += nbytes;
        }
        if let Some(peer) = self.auth_peers.get_mut(to_public_key) {
            peer.bytes_sent += nbytes;
        }
        Ok(())
    }

    fn on_handshake_response(
        &mut self,
        message: EncryptedHandshakeResponse,
        from: SocketAddr,
        packet: &[u8],
    ) -> Result<(), Error> {
        let kind = MessageKind::HandshakeResponse;
        let from_public_key = self
            .socket_addr_to_public_key
            .get(&from)
            .ok_or_else(|| format_error!("no route for {:?} from {}", kind, from))?;
        if !self.hub_to_spokes.contains_key(from_public_key) {
            return Err(format_error!(
                "received handshake response from `{}` (spoke)",
                from_public_key.to_base64()
            ));
        }
        let to_public_key = *self
            .sessions
            .get(&(from, message.receiver_index.as_u32()))
            .ok_or_else(|| {
                format_error!(
                    "no route for {:?} from {} session {}",
                    kind,
                    from,
                    message.receiver_index
                )
            })?;
        let to_socket_addr = self
            .auth_peers
            .get(&to_public_key)
            .ok_or_else(|| {
                format_error!("no route for {:?} from {}: peer not authorized", kind, from)
            })?
            .socket_addr;
        self.socket.send_to(packet, to_socket_addr)?;
        self.sessions
            .insert((from, message.receiver_index.as_u32()), to_public_key);
        self.sessions.insert(
            (to_socket_addr, message.sender_index.as_u32()),
            *from_public_key,
        );
        let nbytes = packet.len() as u64;
        if let Some(peer) = self.auth_peers.get_mut(from_public_key) {
            peer.bytes_received += nbytes;
        }
        if let Some(peer) = self.auth_peers.get_mut(&to_public_key) {
            peer.bytes_sent += nbytes;
        }
        trace!("{}->{} hub->spoke {:?}", from, to_socket_addr, kind);
        Ok(())
    }

    fn on_packet_data(
        &mut self,
        message: EncryptedPacketData,
        from: SocketAddr,
        packet: &[u8],
    ) -> Result<(), Error> {
        let kind = MessageKind::PacketData;
        let from_public_key = self
            .socket_addr_to_public_key
            .get(&from)
            .ok_or_else(|| format_error!("no route for {:?} from {}", kind, from))?;
        let (from_kind, to_kind) = if self.hub_to_spokes.contains_key(from_public_key) {
            ("hub", "spoke")
        } else {
            ("spoke", "hub")
        };
        let to_public_key = self
            .sessions
            .get(&(from, message.receiver_index.as_u32()))
            .ok_or_else(|| {
                format_error!(
                    "no route for {:?} from {} session {}",
                    kind,
                    from,
                    message.receiver_index
                )
            })?;
        if to_public_key == &self.public_key {
            let session = &mut self
                .auth_peers
                .get_mut(from_public_key)
                .ok_or_else(|| {
                    format_error!("no route for {:?} from {}: peer not authorized", kind, from)
                })?
                .session;
            let data = session.receive(&message)?;
            if data.len() >= IP_HEADER_LEN + UDP_HEADER_LEN {
                eprintln!("udp in {} {:?}", data.len(), data);
                let ip = IpPacketView::new(&data);
                let source = ip.source();
                let destination = ip.destination();
                let source_port = ip.source_port();
                let destination_port = ip.destination_port();
                let request = RpcRequest::decode(&data[(IP_HEADER_LEN + UDP_HEADER_LEN)..])?;
                match request.body {
                    RpcRequestBody::SetPeers(mut public_keys) => {
                        // exclude relay's public key from routing
                        public_keys.remove(&self.public_key);
                        for public_key in public_keys.iter() {
                            self.spoke_to_hub.insert(*public_key, *from_public_key);
                        }
                        self.hub_to_spokes.insert(*from_public_key, public_keys);
                        let response = RpcResponse {
                            request_id: request.id,
                            body: RpcResponseBody::SetPeers(Ok(())),
                        };
                        let mut response_bytes = Vec::new();
                        response.encode(&mut response_bytes);
                        let mut ip_packet = IpPacket::new_udp(&response_bytes);
                        ip_packet.set_id(OsRng.gen_range(0_u16..u16::MAX));
                        ip_packet.set_ttl(64);
                        ip_packet.set_source(destination);
                        ip_packet.set_destination(source);
                        ip_packet.set_source_port(destination_port);
                        ip_packet.set_destination_port(source_port);
                        let mut packet = ip_packet.into_udp();
                        while packet.len() % 16 != 0 {
                            packet.push(0);
                        }
                        let view = IpPacketView::new(&packet);
                        eprintln!("source {}:{}", view.source(), view.source_port());
                        eprintln!(
                            "destination {}:{}",
                            view.destination(),
                            view.destination_port()
                        );
                        eprintln!("udp out {} {:?}", packet.len(), packet);
                        let message = session.send(&packet)?;
                        let mut buffer = Vec::new();
                        let mut signer = MacSigner::new(&self.public_key, None);
                        message.encode_with_context(&mut buffer, &mut signer);
                        /*
                        let mut packet = IpPacket::from_raw(data.clone());
                        packet.set_source(destination);
                        packet.set_destination(source);
                        packet.set_source_port(destination_port);
                        packet.set_destination_port(source_port);
                        let packet = packet.data;
                        */
                        //let ip = packet::ip::v4::Packet::new(&packet).unwrap();
                        //eprintln!("ip out {:?}", ip);
                        //let udp = packet::udp::Packet::new(ip.payload());
                        //eprintln!("udp out {:?}", udp);
                        self.socket.send_to(&buffer, from)?;
                    }
                }
            }
            let nbytes = packet.len() as u64;
            if let Some(peer) = self.auth_peers.get_mut(from_public_key) {
                peer.bytes_received += nbytes;
            }
            trace!(
                "{}->local {}->wgx {:?}({})",
                from,
                from_kind,
                kind,
                packet.len(),
            );
        } else {
            let to_socket_addr = self
                .auth_peers
                .get(to_public_key)
                .ok_or_else(|| {
                    format_error!("no route for {:?} from {}: peer not authorized", kind, from)
                })?
                .socket_addr;
            self.socket.send_to(packet, to_socket_addr)?;
            let nbytes = packet.len() as u64;
            if let Some(peer) = self.auth_peers.get_mut(from_public_key) {
                peer.bytes_received += nbytes;
            }
            if let Some(peer) = self.auth_peers.get_mut(to_public_key) {
                peer.bytes_sent += nbytes;
            }
            trace!(
                "{}->{} {}->{} {:?}({})",
                from,
                to_socket_addr,
                from_kind,
                to_kind,
                kind,
                packet.len(),
            );
        }
        Ok(())
    }

    pub(crate) fn status(&self) -> Result<Status, Error> {
        Ok(Status {
            allowed_public_keys: self.allowed_public_keys.clone(),
            public_key: self.public_key,
            listen_port: self.socket.local_addr()?.port(),
            auth_peers: self
                .auth_peers
                .iter()
                .map(|(k, v)| (*k, v.into()))
                .collect(),
        })
    }

    pub(crate) fn routes(&self) -> Result<Routes, Error> {
        Ok(Routes {
            hub_to_spokes: self.hub_to_spokes.clone(),
        })
    }

    pub(crate) fn sessions(&self) -> Result<Sessions, Error> {
        Ok(Sessions {
            sessions: self.sessions.clone(),
        })
    }

    pub(crate) fn export_config(&self) -> Result<String, Error> {
        use std::fmt::Write;
        let mut buf = String::with_capacity(4096);
        writeln!(&mut buf, "# wgx authentication peer")?;
        writeln!(&mut buf, "[Peer]")?;
        writeln!(&mut buf, "PublicKey = {}", self.public_key.to_base64())?;
        let mut internet_addresses = get_internet_addresses()?;
        internet_addresses.sort();
        let mut iter = internet_addresses.into_iter();
        let port = self.socket.local_addr()?.port();
        match iter.next() {
            Some(addr) => match addr {
                IpAddr::V4(addr) => writeln!(&mut buf, "Endpoint = {}:{}", addr, port)?,
                IpAddr::V6(addr) => writeln!(&mut buf, "Endpoint = [{}]:{}", addr, port)?,
            },
            None => {
                writeln!(&mut buf, "# no internet addresses found")?;
                writeln!(&mut buf, "# Endpoint = ENDPOINT:{}", port)?;
            }
        }
        for addr in iter {
            match addr {
                IpAddr::V4(addr) => writeln!(&mut buf, "# Endpoint = {}:{}", addr, port)?,
                IpAddr::V6(addr) => writeln!(&mut buf, "# Endpoint = [{}]:{}", addr, port)?,
            }
        }
        writeln!(&mut buf, "PersistentKeepalive = 23")?;
        writeln!(&mut buf, "# no IPs are allowed")?;
        writeln!(&mut buf, "AllowedIPs =")?;
        Ok(buf)
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub(crate) fn advance(&mut self, now: SystemTime) {
        while let Some(event) = self.events.peek() {
            if event.expiry > now {
                break;
            }
            let event = match self.events.pop() {
                Some(event) => event,
                None => continue,
            };
            if let Some(auth_peer) = self.auth_peers.get(&event.public_key) {
                if event.session_index != auth_peer.session.sender_index() {
                    // ignore old sessions
                    continue;
                }
            }
            if let Some(peer) = self.auth_peers.remove(&event.public_key) {
                self.sessions
                    .remove(&(peer.socket_addr, peer.session.sender_index().as_u32()));
                self.socket_addr_to_public_key.remove(&peer.socket_addr);
                if let Some(spokes) = self.hub_to_spokes.remove(&event.public_key) {
                    for spoke in spokes.into_iter() {
                        self.spoke_to_hub.remove(&spoke);
                    }
                }
            }
        }
    }

    pub(crate) fn next_event_time(&self) -> Option<SystemTime> {
        self.events.peek().map(|event| event.expiry)
    }
}

struct AuthPeer {
    session: Session,
    socket_addr: SocketAddr,
    created_at: SystemTime,
    bytes_received: u64,
    bytes_sent: u64,
}

impl AuthPeer {
    fn expiry(&self) -> SystemTime {
        self.created_at + SESSION_TIMEOUT
    }
}

impl From<&AuthPeer> for wgx::AuthPeer {
    fn from(other: &AuthPeer) -> Self {
        Self {
            socket_addr: other.socket_addr,
            latest_handshake: other.created_at,
            bytes_received: other.bytes_received,
            bytes_sent: other.bytes_sent,
        }
    }
}

struct ExpiryEvent {
    expiry: SystemTime,
    public_key: PublicKey,
    session_index: SessionIndex,
}

impl PartialEq for ExpiryEvent {
    fn eq(&self, other: &Self) -> bool {
        // inverse
        other.expiry.eq(&self.expiry)
    }
}

impl Eq for ExpiryEvent {}

impl PartialOrd for ExpiryEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExpiryEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // inverse
        other.expiry.cmp(&self.expiry)
    }
}

const MAX_PACKET_SIZE: usize = 65535;
const IP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);
