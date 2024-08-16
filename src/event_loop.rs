use std::net::Ipv4Addr;
use std::net::SocketAddr;

use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use wgproto::Context;
use wgproto::DecodeWithContext;
use wgproto::InputBuffer;
use wgproto::Message;
use wgproto::PublicKey;
use wgproto::Responder;
use wgproto::Session;
use wgproto::SessionIndex;

use crate::format_error;
use crate::Config;
use crate::Error;
use crate::PeerType;
use crate::ServerConfig;
use crate::ToBase64;

pub(crate) struct EventLoop {
    poll: Poll,
    servers: Vec<Server>,
}

impl EventLoop {
    pub(crate) fn new(config: Config) -> Result<Self, Error> {
        let mut servers: Vec<Server> = Vec::with_capacity(config.servers.len());
        let poll = Poll::new()?;
        for (i, server) in config.servers.into_iter().enumerate() {
            let socket_addr =
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), server.listen_port.into());
            eprintln!("listen on {}", socket_addr);
            let mut socket = UdpSocket::bind(socket_addr)?;
            poll.registry()
                .register(&mut socket, Token(i), Interest::READABLE)?;
            servers.push(Server {
                socket_addr,
                socket,
                public_key: (&server.private_key).into(),
                hub: Default::default(),
                spokes: Default::default(),
                other_peers: Default::default(),
                config: server,
            });
        }
        Ok(Self { poll, servers })
    }

    pub(crate) fn waker(&self) -> Result<Waker, Error> {
        Ok(Waker::new(self.poll.registry(), WAKE_TOKEN)?)
    }

    pub(crate) fn run(mut self) -> Result<(), Error> {
        let mut events = Events::with_capacity(MAX_EVENTS);
        let mut buffer = [0_u8; MAX_PACKET_SIZE];
        loop {
            self.dump();
            events.clear();
            match self.poll.poll(&mut events, None) {
                Ok(()) => Ok(()),
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(()),
                other => other,
            }?;
            for event in events.iter() {
                if event.token() == WAKE_TOKEN {
                    return Ok(());
                }
                let i = event.token().0;
                let peer = match self.servers.get_mut(i) {
                    Some(peer) => peer,
                    None => continue,
                };
                if event.is_readable() {
                    if let Err(e) = Self::process_packet(peer, buffer.as_mut_slice()) {
                        eprintln!("failed to process packet: {}", e);
                    }
                }
            }
        }
    }

    fn process_packet(server: &mut Server, buffer: &mut [u8]) -> Result<(), Error> {
        let (n, from) = server.socket.recv_from(buffer)?;
        let packet = &buffer[..n];
        let mut buffer = InputBuffer::new(packet);
        let mut context = Context::new(&server.public_key);
        let message = Message::decode_with_context(&mut buffer, &mut context)?;
        eprintln!("{:?} from {}", message.get_type(), from);
        match message {
            Message::HandshakeInitiation(message) => {
                let sender_index = message.sender_index;
                let result = Responder::respond(
                    server.public_key,
                    server.config.private_key.clone(),
                    &server.config.preshared_key,
                    message,
                );
                match result {
                    Ok((session, initiation, response_bytes)) => {
                        let peer = match server
                            .config
                            .peers
                            .iter()
                            .find(|peer| peer.public_key == initiation.static_public)
                        {
                            Some(peer) => peer,
                            None => {
                                return Err(format_error!(
                                    "untrusted public key: `{}`",
                                    initiation.static_public.to_base64()
                                ))
                            }
                        };
                        match peer.peer_type {
                            PeerType::Hub => {
                                let new_hub = Hub {
                                    public_key: initiation.static_public,
                                    session,
                                    socket_addr: from,
                                };
                                server.hub = Some(new_hub);
                            }
                            PeerType::Spoke => {
                                server.spokes.push(Spoke {
                                    public_key: initiation.static_public,
                                    session,
                                    socket_addr: from,
                                });
                            }
                        }
                        server.socket.send_to(response_bytes.as_slice(), from)?;
                    }
                    Err(e) => match server.hub.as_mut() {
                        Some(hub) => {
                            if from == hub.socket_addr {
                                return Err(e.into());
                            }
                            server.other_peers.push(OtherPeer {
                                socket_addr: from,
                                session_index: sender_index,
                                status: OtherPeerStatus::Pending,
                                peer_type: PeerType::Spoke,
                            });
                            eprintln!("forward handshake-initiation from {} to hub", from);
                            server.socket.send_to(packet, hub.socket_addr)?;
                        }
                        None => return Err(e.into()),
                    },
                }
            }
            Message::HandshakeResponse(message) => match server.hub.as_mut() {
                Some(hub) => {
                    eprintln!(
                        "handshake-response from {} receiver {}",
                        from, message.receiver_index
                    );
                    if from == hub.socket_addr {
                        if let Some(other_peer) = server
                            .other_peers
                            .iter_mut()
                            .find(|other_peer| other_peer.session_index == message.receiver_index)
                        {
                            eprintln!("authorize");
                            other_peer.status = OtherPeerStatus::Authorized;
                            server.socket.send_to(packet, other_peer.socket_addr)?;
                        }
                        // add hub as a peer
                        server.other_peers.push(OtherPeer {
                            socket_addr: hub.socket_addr,
                            session_index: message.sender_index,
                            status: OtherPeerStatus::Authorized,
                            peer_type: PeerType::Hub,
                        });
                    }
                }
                None => return Err(Error::other("no hub")),
            },
            Message::PacketData(message) => {
                match server.hub.as_mut() {
                    Some(hub) => {
                        if from == hub.socket_addr {
                            if message.receiver_index == hub.session.sender_index() {
                                let data = hub.session.receive(&message)?;
                                eprintln!("received {:?}", data);
                            } else if let Some(other_peer) =
                                server.other_peers.iter_mut().find(|other_peer| {
                                    other_peer.session_index == message.receiver_index
                                })
                            {
                                eprintln!("send packet from hub to {}", other_peer.socket_addr);
                                server.socket.send_to(packet, other_peer.socket_addr)?;
                            }
                        } else {
                            eprintln!("send packet from {} to hub", from);
                            server.socket.send_to(packet, hub.socket_addr)?;
                        }
                    }
                    None => {
                        // TODO
                    }
                }
            }
        }
        Ok(())
    }

    fn dump(&self) {
        eprintln!(
            "{:<23}{:<23}{:<23}{:<23}{:<23}{:<46}",
            "Local", "Type", "Status", "Remote", "Session", "PublicKey"
        );
        for server in self.servers.iter() {
            if let Some(hub) = server.hub.as_ref() {
                eprintln!(
                    "{:<23}{:<23}{:<23}{:<23}{:<23}{}",
                    server.socket_addr,
                    "hub-auth",
                    "authorized",
                    hub.socket_addr,
                    hub.session.sender_index(),
                    hub.public_key.to_base64(),
                );
            }
            for spoke in server.spokes.iter() {
                eprintln!(
                    "{:<23}{:<23}{:<23}{:<23}{:<23}{}",
                    server.socket_addr,
                    "spoke-auth",
                    "authorized",
                    spoke.socket_addr,
                    spoke.session.sender_index(),
                    spoke.public_key.to_base64(),
                );
            }
            for other_peer in server.other_peers.iter() {
                eprintln!(
                    "{:<23}{:<23}{:<23}{:<23}{:<23}",
                    server.socket_addr,
                    other_peer.peer_type.as_str(),
                    other_peer.status.as_str(),
                    other_peer.socket_addr,
                    other_peer.session_index,
                );
            }
        }
        eprintln!("-");
    }
}

struct Server {
    socket_addr: SocketAddr,
    socket: UdpSocket,
    public_key: PublicKey,
    hub: Option<Hub>,
    spokes: Vec<Spoke>,
    other_peers: Vec<OtherPeer>,
    config: ServerConfig,
}

struct Hub {
    public_key: PublicKey,
    session: Session,
    socket_addr: SocketAddr,
}

struct Spoke {
    public_key: PublicKey,
    session: Session,
    socket_addr: SocketAddr,
}

struct OtherPeer {
    socket_addr: SocketAddr,
    session_index: SessionIndex,
    status: OtherPeerStatus,
    peer_type: PeerType,
}

enum OtherPeerStatus {
    Pending,
    Authorized,
}

impl OtherPeerStatus {
    fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
        }
    }
}

const MAX_EVENTS: usize = 1024;
const MAX_PACKET_SIZE: usize = 65535;
const WAKE_TOKEN: Token = Token(usize::MAX);
