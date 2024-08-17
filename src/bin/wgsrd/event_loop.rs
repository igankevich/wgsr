use std::collections::HashMap;
use std::fs::create_dir_all;
use std::fs::rename;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::path::Path;
use std::path::PathBuf;

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
use wgproto::PresharedKey;
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgproto::Responder;
use wgproto::Session;
use wgsr::EncodeDecode;
use wgsr::Peer;
use wgsr::PeerKind;
use wgsr::PeerStatus;
use wgsr::Request;
use wgsr::RequestError;
use wgsr::Response;
use wgsr::Status;
use wgsr::ToBase64;
use wgsr::MAX_REQUEST_SIZE;
use wgsr::MAX_RESPONSE_SIZE;

use crate::format_error;
use crate::get_internet_addresses;
use crate::Config;
use crate::Error;
use crate::PeerConfig;
use crate::ServerConfig;

pub(crate) struct EventLoop {
    config_file: PathBuf,
    poll: Poll,
    servers: HashMap<u16, Server>,
    unix_server: UnixListener,
    unix_clients: HashMap<usize, UnixClient>,
}

impl EventLoop {
    pub(crate) fn new(config: Config, config_file: PathBuf) -> Result<Self, Error> {
        let mut servers = HashMap::with_capacity(config.servers.len());
        let poll = Poll::new()?;
        for (i, server) in config.servers.into_iter().enumerate() {
            let socket_addr =
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), server.listen_port.into());
            eprintln!("listen on {}", socket_addr);
            let mut socket = UdpSocket::bind(socket_addr)?;
            poll.registry()
                .register(&mut socket, Token(i), Interest::READABLE)?;
            servers.insert(
                server.listen_port.into(),
                Server {
                    socket_addr,
                    socket,
                    public_key: (&server.private_key).into(),
                    hub: Default::default(),
                    spokes: Default::default(),
                    other_peers: Default::default(),
                    config: server,
                },
            );
        }
        // unix socket
        if let Some(directory) = config.unix_socket_path.parent() {
            create_dir_all(directory)?;
        }
        let mut unix_server = UnixListener::bind(config.unix_socket_path.as_path())?;
        poll.registry()
            .register(&mut unix_server, UNIX_SERVER_TOKEN, Interest::READABLE)?;
        Ok(Self {
            config_file,
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
                            &mut self.servers,
                            &mut self.poll,
                            self.config_file.as_path(),
                        )
                    }
                    Token(i) => {
                        let port = (i - RELAY_TOKEN_MIN) as u16;
                        let peer = match self.servers.get_mut(&port) {
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
                        match peer.kind {
                            PeerKind::Hub => {
                                let new_hub = Hub {
                                    public_key: initiation.static_public,
                                    session,
                                    socket_addr: from,
                                };
                                server.hub = Some(new_hub);
                            }
                            PeerKind::Spoke => {
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
                                kind: PeerKind::Spoke,
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
                            kind: PeerKind::Hub,
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
        servers: &mut HashMap<u16, Server>,
        poll: &mut Poll,
        config_file: &Path,
    ) -> Result<(), Error> {
        let mut interest: Option<Interest> = None;
        if event.is_readable() {
            client.fill_buf()?;
            while let Some(request) = client.read_request()? {
                let response = match request {
                    Request::Status => Response::Status(Ok(Status {
                        servers: servers.iter().map(|(_, v)| v.into()).collect(),
                    })),
                    Request::RelayAdd {
                        listen_port,
                        persistent,
                    } => {
                        let response =
                            Self::add_relay(listen_port, persistent, config_file, poll, servers)
                                .map_err(RequestError::map);
                        Response::RelayAdd(response)
                    }
                    Request::RelayRemove {
                        listen_port,
                        persistent,
                    } => {
                        let response =
                            Self::remove_relay(listen_port, persistent, config_file, servers)
                                .map_err(RequestError::map);
                        Response::RelayRemove(response)
                    }
                    Request::HubAdd {
                        listen_port,
                        public_key,
                        persistent,
                    } => {
                        let response = Self::add_hub(
                            listen_port,
                            public_key,
                            persistent,
                            config_file,
                            servers,
                        )
                        .map_err(RequestError::map);
                        Response::HubAdd(response)
                    }
                    Request::HubRemove {
                        listen_port,
                        public_key,
                        persistent,
                    } => {
                        let response = Self::remove_hub(
                            listen_port,
                            public_key,
                            persistent,
                            config_file,
                            servers,
                        )
                        .map_err(RequestError::map);
                        Response::HubRemove(response)
                    }
                    Request::SpokeAdd {
                        listen_port,
                        public_key,
                        persistent,
                    } => {
                        let response = Self::add_spoke(
                            listen_port,
                            public_key,
                            persistent,
                            config_file,
                            servers,
                        )
                        .map_err(RequestError::map);
                        Response::SpokeAdd(response)
                    }
                    Request::SpokeRemove {
                        listen_port,
                        public_key,
                        persistent,
                    } => {
                        let response = Self::remove_spoke(
                            listen_port,
                            public_key,
                            persistent,
                            config_file,
                            servers,
                        )
                        .map_err(RequestError::map);
                        Response::SpokeRemove(response)
                    }
                    Request::Export { listen_port } => {
                        let response =
                            Self::export_config(listen_port, servers).map_err(RequestError::map);
                        Response::Export(response)
                    }
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
        for server in self.servers.values() {
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
                    other_peer.kind.as_str(),
                    other_peer.status.as_str(),
                    other_peer.socket_addr,
                    other_peer.session_index,
                );
            }
        }
        eprintln!("-");
    }

    fn add_relay(
        listen_port: Option<NonZeroU16>,
        persistent: bool,
        config_file: &Path,
        poll: &mut Poll,
        servers: &mut HashMap<u16, Server>,
    ) -> Result<NonZeroU16, Error> {
        if servers.len() == MAX_RELAYS {
            return Err(format_error!("max. no. of relays reached"));
        }
        let listen_port: u16 = match listen_port {
            Some(listen_port) => listen_port.into(),
            None => loop {
                let port: u16 = OsRng.gen_range(RELAY_TOKEN_MIN..(RELAY_TOKEN_MAX + 1)) as u16;
                if !servers.contains_key(&port) {
                    break port;
                }
            },
        };
        let socket_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), listen_port);
        let private_key = PrivateKey::random();
        let preshared_key = PresharedKey::random();
        eprintln!("listen on {}", socket_addr);
        let mut socket = UdpSocket::bind(socket_addr)?;
        poll.registry()
            .register(&mut socket, Token(listen_port as usize), Interest::READABLE)?;
        let non_zero_listen_port: NonZeroU16 = listen_port.try_into().map_err(Error::other)?;
        let server = Server {
            socket_addr,
            socket,
            public_key: (&private_key).into(),
            hub: Default::default(),
            spokes: Default::default(),
            other_peers: Default::default(),
            config: ServerConfig {
                private_key,
                preshared_key,
                listen_port: non_zero_listen_port,
                peers: Default::default(),
            },
        };
        if persistent {
            update_config(config_file, |config| {
                config.servers.push(server.config.clone());
                Ok(())
            })?;
        }
        servers.insert(listen_port, server);
        Ok(non_zero_listen_port)
    }

    fn remove_relay(
        listen_port: NonZeroU16,
        persistent: bool,
        config_file: &Path,
        servers: &mut HashMap<u16, Server>,
    ) -> Result<(), Error> {
        let port: u16 = listen_port.into();
        if servers.remove(&port).is_none() {
            return Err(format_error!("no relay with listen-port `{}`", listen_port));
        }
        if persistent {
            update_config(config_file, |config| {
                config
                    .servers
                    .retain(|server| server.listen_port != listen_port);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn add_hub(
        listen_port: NonZeroU16,
        public_key: PublicKey,
        persistent: bool,
        config_file: &Path,
        servers: &mut HashMap<u16, Server>,
    ) -> Result<(), Error> {
        let port: u16 = listen_port.into();
        let relay = servers
            .get_mut(&port)
            .ok_or_else(|| format_error!("no relay with listen port `{}`", listen_port))?;
        if relay
            .config
            .peers
            .iter()
            .any(|peer| peer.public_key == public_key)
        {
            return Err(format_error!(
                "another hub/spoke with public key `{}` is attached to listen port `{}`",
                public_key.to_base64(),
                listen_port
            ));
        }
        let peer = PeerConfig {
            public_key,
            kind: PeerKind::Hub,
        };
        relay.config.peers.push(peer.clone());
        if persistent {
            update_config(config_file, |config| {
                let server = config
                    .servers
                    .iter_mut()
                    .find(|server| server.listen_port == listen_port)
                    .ok_or_else(|| {
                        format_error!(
                            "no relay with listen port `{}` in `{}`",
                            listen_port,
                            config_file.display()
                        )
                    })?;
                server.peers.push(peer);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn remove_hub(
        listen_port: NonZeroU16,
        public_key: PublicKey,
        persistent: bool,
        config_file: &Path,
        servers: &mut HashMap<u16, Server>,
    ) -> Result<(), Error> {
        let port: u16 = listen_port.into();
        let relay = servers
            .get_mut(&port)
            .ok_or_else(|| format_error!("no relay with listen port `{}`", listen_port))?;
        let old_len = relay.config.peers.len();
        relay
            .config
            .peers
            .retain(|peer| peer.kind != PeerKind::Hub || peer.public_key != public_key);
        let new_len = relay.config.peers.len();
        if new_len != old_len {
            return Err(format_error!(
                "no hub with public key `{}`",
                public_key.to_base64()
            ));
        }
        relay.hub = None;
        if persistent {
            update_config(config_file, |config| {
                let server = config
                    .servers
                    .iter_mut()
                    .find(|server| server.listen_port == listen_port)
                    .ok_or_else(|| {
                        format_error!(
                            "no relay with listen port `{}` in `{}`",
                            listen_port,
                            config_file.display()
                        )
                    })?;
                server
                    .peers
                    .retain(|peer| peer.kind != PeerKind::Hub || peer.public_key != public_key);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn export_config(
        listen_port: NonZeroU16,
        servers: &mut HashMap<u16, Server>,
    ) -> Result<String, Error> {
        use std::fmt::Write;
        let port: u16 = listen_port.into();
        let relay = servers
            .get_mut(&port)
            .ok_or_else(|| format_error!("no relay with listen port `{}`", listen_port))?;
        let mut buf = String::with_capacity(4096);
        writeln!(&mut buf, "# wgsr authentication peer")?;
        writeln!(&mut buf, "[Peer]")?;
        writeln!(&mut buf, "PublicKey = {}", relay.public_key.to_base64())?;
        let mut internet_addresses = get_internet_addresses()?;
        internet_addresses.sort();
        let mut iter = internet_addresses.into_iter();
        match iter.next() {
            Some(addr) => {
                writeln!(&mut buf, "Endpoint = {}:{}", addr, relay.socket_addr.port())?;
            }
            None => {
                writeln!(&mut buf, "# no internet addresses found")?;
                writeln!(&mut buf, "# Endpoint = ")?;
            }
        }
        for addr in iter {
            writeln!(
                &mut buf,
                "# Endpoint = {}:{}",
                addr,
                relay.socket_addr.port()
            )?;
        }
        writeln!(&mut buf, "PersistentKeepalive = 23")?;
        writeln!(&mut buf, "AllowedIPs =")?;
        Ok(buf)
    }

    fn add_spoke(
        listen_port: NonZeroU16,
        public_key: PublicKey,
        persistent: bool,
        config_file: &Path,
        servers: &mut HashMap<u16, Server>,
    ) -> Result<(), Error> {
        let port: u16 = listen_port.into();
        let relay = servers
            .get_mut(&port)
            .ok_or_else(|| format_error!("no relay with listen port `{}`", listen_port))?;
        if relay
            .config
            .peers
            .iter()
            .any(|peer| peer.public_key == public_key)
        {
            return Err(format_error!(
                "another hub/spoke with public key `{}` is attached to listen port `{}`",
                public_key.to_base64(),
                listen_port
            ));
        }
        let peer = PeerConfig {
            public_key,
            kind: PeerKind::Spoke,
        };
        relay.config.peers.push(peer.clone());
        if persistent {
            update_config(config_file, |config| {
                let server = config
                    .servers
                    .iter_mut()
                    .find(|server| server.listen_port == listen_port)
                    .ok_or_else(|| {
                        format_error!(
                            "no relay with listen port `{}` in `{}`",
                            listen_port,
                            config_file.display()
                        )
                    })?;
                server.peers.push(peer);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn remove_spoke(
        listen_port: NonZeroU16,
        public_key: PublicKey,
        persistent: bool,
        config_file: &Path,
        servers: &mut HashMap<u16, Server>,
    ) -> Result<(), Error> {
        let port: u16 = listen_port.into();
        let relay = servers
            .get_mut(&port)
            .ok_or_else(|| format_error!("no relay with listen port `{}`", listen_port))?;
        let old_len = relay.config.peers.len();
        relay.spokes.retain(|spoke| spoke.public_key != public_key);
        relay
            .config
            .peers
            .retain(|peer| peer.kind != PeerKind::Spoke || peer.public_key != public_key);
        let new_len = relay.config.peers.len();
        if new_len != old_len {
            return Err(format_error!(
                "no hub with public key `{}`",
                public_key.to_base64()
            ));
        }
        if persistent {
            update_config(config_file, |config| {
                let server = config
                    .servers
                    .iter_mut()
                    .find(|server| server.listen_port == listen_port)
                    .ok_or_else(|| {
                        format_error!(
                            "no relay with listen port `{}` in `{}`",
                            listen_port,
                            config_file.display()
                        )
                    })?;
                server
                    .peers
                    .retain(|peer| peer.kind != PeerKind::Spoke || peer.public_key != public_key);
                Ok(())
            })?;
        }
        Ok(())
    }
}

fn update_config<F>(config_file: &Path, f: F) -> Result<(), Error>
where
    F: FnOnce(&'_ mut Config) -> Result<(), Error>,
{
    let mut config = Config::open(config_file)?;
    f(&mut config)?;
    let tmp_config_file = get_tmp_file(config_file)?;
    config.save(tmp_config_file.as_path())?;
    rename(tmp_config_file.as_path(), config_file)?;
    Ok(())
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

fn get_tmp_file(path: &Path) -> Result<PathBuf, Error> {
    let filename = path
        .file_name()
        .ok_or_else(|| format_error!("invalid file path: `{}`", path.display()))?;
    let filename = format!(".{}.tmp", Path::new(filename).display());
    Ok(match path.parent() {
        Some(parent) => parent.join(filename),
        None => filename.into(),
    })
}

const MAX_EVENTS: usize = 1024;
const MAX_PACKET_SIZE: usize = 65535;
const WAKE_TOKEN: Token = Token(usize::MAX);
const UNIX_SERVER_TOKEN: Token = Token(usize::MAX - 1);
const MAX_UNIX_CLIENTS: usize = 1000;
const UNIX_TOKEN_MAX: usize = usize::MAX - 2;
const UNIX_TOKEN_MIN: usize = UNIX_TOKEN_MAX + 1 - MAX_UNIX_CLIENTS;
const RELAY_TOKEN_MAX: usize = UNIX_TOKEN_MIN - 1;
const RELAY_TOKEN_MIN: usize = 1001;
const MAX_RELAYS: usize = RELAY_TOKEN_MAX - RELAY_TOKEN_MIN + 1;
