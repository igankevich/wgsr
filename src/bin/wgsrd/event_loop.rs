use std::collections::HashMap;
use std::fs::create_dir_all;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use bincode::error::DecodeError;
use mio::event::Event;
use mio::net::UdpSocket;
use mio::net::UnixListener;
use mio::net::UnixStream;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use rand::Rng;
use rand_core::OsRng;
use wgproto::Context;
use wgproto::DecodeWithContext;
use wgproto::InputBuffer;
use wgproto::Message;
use wgproto::PublicKey;
use wgproto::Responder;
use wgproto::Session;
use wgsr::format_error;
use wgsr::EncodeDecode;
use wgsr::Error;
use wgsr::Peer;
use wgsr::PeerStatus;
use wgsr::PeerType;
use wgsr::Request;
use wgsr::Response;
use wgsr::Status;
use wgsr::ToBase64;
use wgsr::MAX_REQUEST_SIZE;
use wgsr::MAX_RESPONSE_SIZE;

use crate::Config;
use crate::ServerConfig;

pub(crate) struct EventLoop {
    poll: Poll,
    servers: Vec<Server>,
    unix_server: UnixListener,
    unix_clients: HashMap<usize, UnixClient>,
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
        // unix socket
        if let Some(directory) = config.unix_socket_path.parent() {
            create_dir_all(directory)?;
        }
        let mut unix_server = UnixListener::bind(config.unix_socket_path.as_path())?;
        poll.registry()
            .register(&mut unix_server, UNIX_SERVER_TOKEN, Interest::READABLE)?;
        Ok(Self {
            poll,
            servers,
            unix_server,
            unix_clients: Default::default(),
        })
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
                let ret = match event.token() {
                    WAKE_TOKEN => return Ok(()),
                    UNIX_SERVER_TOKEN => {
                        if event.is_readable() {
                            self.accept_unix_connections()
                        } else {
                            Ok(())
                        }
                    }
                    Token(i) if (UNIX_TOKEN_MIN..=UNIX_TOKEN_MAX).contains(&i) => {
                        let i = i - UNIX_TOKEN_MIN;
                        if event.is_error() {
                            self.unix_clients.remove(&i);
                            continue;
                        }
                        let client = match self.unix_clients.get_mut(&i) {
                            Some(client) => client,
                            None => continue,
                        };
                        Self::process_unix_client_event(
                            event,
                            client,
                            &self.servers,
                            &mut self.poll,
                        )
                    }
                    Token(i) => {
                        let peer = match self.servers.get_mut(i) {
                            Some(peer) => peer,
                            None => continue,
                        };
                        if event.is_readable() {
                            Self::process_packet(peer, buffer.as_mut_slice())
                        } else {
                            Ok(())
                        }
                    }
                };
                if let Err(e) = ret {
                    eprintln!("{}", e);
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
                            server.other_peers.push(Peer {
                                socket_addr: from,
                                session_index: sender_index.into(),
                                status: PeerStatus::Pending,
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
                        if let Some(other_peer) = server.other_peers.iter_mut().find(|other_peer| {
                            other_peer.session_index == message.receiver_index.as_u32()
                        }) {
                            eprintln!("authorize");
                            other_peer.status = PeerStatus::Authorized;
                            server.socket.send_to(packet, other_peer.socket_addr)?;
                        }
                        // add hub as a peer
                        server.other_peers.push(Peer {
                            socket_addr: hub.socket_addr,
                            session_index: message.sender_index.into(),
                            status: PeerStatus::Authorized,
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
                                    other_peer.session_index == message.receiver_index.as_u32()
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

    fn accept_unix_connections(&mut self) -> Result<(), Error> {
        use std::collections::hash_map::Entry;
        loop {
            let (mut stream, from) = match self.unix_server.accept() {
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // no more connections to accept
                    break;
                }
                other => other,
            }?;
            eprintln!("accepted connection from {:?}", from);
            if self.unix_clients.len() == MAX_UNIX_CLIENTS {
                return Err(Error::other("max no. of unix clients reached"));
            }
            loop {
                let i = OsRng.gen_range(UNIX_TOKEN_MIN..(UNIX_TOKEN_MAX + 1));
                if let Entry::Vacant(v) = self.unix_clients.entry(i) {
                    self.poll
                        .registry()
                        .register(&mut stream, Token(i), Interest::READABLE)?;
                    v.insert(UnixClient::new(stream)?);
                    break;
                }
            }
        }
        Ok(())
    }

    fn process_unix_client_event(
        event: &Event,
        client: &mut UnixClient,
        servers: &[Server],
        poll: &mut Poll,
    ) -> Result<(), Error> {
        let mut interest: Option<Interest> = None;
        if event.is_readable() {
            client.fill_buf()?;
            while let Some(request) = client.read_request()? {
                let response = match request {
                    Request::Status => Response::Status(Ok(Status {
                        servers: servers.iter().map(Into::into).collect(),
                    })),
                };
                client.send_response(&response)?;
            }
            if !client.flush()? {
                interest = Some(Interest::READABLE | Interest::WRITABLE);
            }
        }
        if event.is_writable() && client.flush()? {
            interest = Some(Interest::READABLE);
        }
        if let Some(interest) = interest {
            poll.registry()
                .reregister(&mut SourceFd(&client.fd), UNIX_SERVER_TOKEN, interest)?;
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
    other_peers: Vec<Peer>,
    config: ServerConfig,
}

impl From<&Server> for wgsr::Server {
    fn from(other: &Server) -> Self {
        Self {
            socket_addr: other.socket_addr,
            hub: other.hub.as_ref().map(Into::into),
            spokes: other.spokes.iter().map(Into::into).collect(),
            peers: other.other_peers.clone(),
        }
    }
}

struct Hub {
    public_key: PublicKey,
    session: Session,
    socket_addr: SocketAddr,
}

impl From<&Hub> for wgsr::Hub {
    fn from(other: &Hub) -> Self {
        Self {
            socket_addr: other.socket_addr,
            public_key: other.public_key,
            session_index: other.session.sender_index().into(),
        }
    }
}

type Spoke = Hub;

struct UnixClient {
    fd: RawFd,
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
}

impl UnixClient {
    fn new(stream: UnixStream) -> Result<Self, Error> {
        let stream: std::os::unix::net::UnixStream = stream.into();
        let fd = stream.as_raw_fd();
        let input_stream = UnixStream::from_std(stream.try_clone()?);
        let output_stream = UnixStream::from_std(stream);
        Ok(Self {
            fd,
            reader: BufReader::with_capacity(MAX_REQUEST_SIZE, input_stream),
            writer: BufWriter::with_capacity(MAX_RESPONSE_SIZE, output_stream),
        })
    }

    fn fill_buf(&mut self) -> Result<(), Error> {
        self.reader.fill_buf()?;
        Ok(())
    }

    fn read_request(&mut self) -> Result<Option<Request>, Error> {
        match Request::decode(&mut self.reader) {
            Ok(request) => Ok(Some(request)),
            Err(DecodeError::UnexpectedEnd { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn send_response(&mut self, response: &Response) -> Result<(), Error> {
        response.encode(&mut self.writer)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<bool, Error> {
        self.writer.flush()?;
        Ok(self.writer.buffer().is_empty())
    }
}

const MAX_EVENTS: usize = 1024;
const MAX_PACKET_SIZE: usize = 65535;
const WAKE_TOKEN: Token = Token(usize::MAX);
const UNIX_SERVER_TOKEN: Token = Token(usize::MAX - 1);
const MAX_UNIX_CLIENTS: usize = 1000;
const UNIX_TOKEN_MAX: usize = usize::MAX - 2;
const UNIX_TOKEN_MIN: usize = UNIX_TOKEN_MAX + 1 - MAX_UNIX_CLIENTS;
