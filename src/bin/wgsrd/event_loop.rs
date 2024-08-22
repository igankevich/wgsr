use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::create_dir_all;
use std::fs::remove_file;
use std::fs::rename;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
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
use static_assertions::const_assert;
use wgproto::DecodeWithContext;
use wgproto::EncodeWithContext;
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
use wgsr::EncodeDecode;
use wgsr::ExportFormat;
use wgsr::Request;
use wgsr::RequestError;
use wgsr::Response;
use wgsr::RpcRequest;
use wgsr::RpcRequestBody;
use wgsr::RpcResponse;
use wgsr::RpcResponseBody;
use wgsr::Status;
use wgsr::ToBase64;
use wgsr::MAX_REQUEST_SIZE;
use wgsr::MAX_RESPONSE_SIZE;

use crate::format_error;
use crate::get_internet_addresses;
use crate::AllowedPublicKeys;
use crate::Config;
use crate::Error;

pub(crate) struct EventLoop {
    #[allow(dead_code)]
    config_file: PathBuf,
    poll: Poll,
    udp_server: UdpServer,
    unix_server: UnixListener,
    unix_clients: HashMap<usize, UnixClient>,
}

impl EventLoop {
    pub(crate) fn new(config: Config, config_file: PathBuf) -> Result<Self, Error> {
        let poll = Poll::new()?;
        let socket_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), config.listen_port.into());
        let mut udp_socket = UdpSocket::bind(socket_addr)?;
        poll.registry()
            .register(&mut udp_socket, UDP_SERVER_TOKEN, Interest::READABLE)?;
        // unix socket
        if let Some(directory) = config.unix_socket_path.parent() {
            create_dir_all(directory)?;
        }
        let _ = remove_file(config.unix_socket_path.as_path());
        let mut unix_server = UnixListener::bind(config.unix_socket_path.as_path())?;
        poll.registry()
            .register(&mut unix_server, UNIX_SERVER_TOKEN, Interest::READABLE)?;
        Ok(Self {
            config_file,
            poll,
            udp_server: UdpServer {
                socket: udp_socket,
                public_key: (&config.private_key).into(),
                private_key: config.private_key,
                preshared_key: [0_u8; 32].into(),
                auth_peers: Default::default(),
                hub_to_spokes: Default::default(),
                spoke_to_hub: Default::default(),
                allowed_public_keys: config.allowed_public_keys,
                socket_addr_to_public_key: Default::default(),
                session_to_destination: Default::default(),
            },
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
                    UDP_SERVER_TOKEN => {
                        if event.is_readable() {
                            Self::process_packet(&mut self.udp_server, buffer.as_mut_slice())
                        } else {
                            Ok(())
                        }
                    }
                    UNIX_SERVER_TOKEN => {
                        if event.is_readable() {
                            self.accept_unix_connections()
                        } else {
                            Ok(())
                        }
                    }
                    Token(i) if (UNIX_TOKEN_MIN..=UNIX_TOKEN_MAX).contains(&i) => {
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
                            &mut self.udp_server,
                            &mut self.poll,
                        )
                    }
                    Token(i) => Err(format_error!("unknown event {}", i)),
                };
                if let Err(e) = ret {
                    eprintln!("{}", e);
                }
            }
        }
    }

    fn dump(&self) {
        for (public_key, peer) in self.udp_server.auth_peers.iter() {
            eprintln!(
                "auth-peer {} {} {}->{}",
                public_key.to_base64(),
                peer.socket_addr,
                peer.session.sender_index(),
                peer.session.receiver_index()
            );
        }
        for (hub, spokes) in self.udp_server.hub_to_spokes.iter() {
            for spoke in spokes.iter() {
                eprintln!("edge {} {}", hub.to_base64(), spoke.to_base64());
            }
        }
        for ((sender_socket_addr, receiver_index), receiver_public_key) in
            self.udp_server.session_to_destination.iter()
        {
            eprintln!(
                "route {} {} -> {}",
                sender_socket_addr,
                receiver_index,
                receiver_public_key.to_base64()
            );
        }
    }

    fn process_packet(server: &mut UdpServer, buffer: &mut [u8]) -> Result<(), Error> {
        let (n, from) = server.socket.recv_from(buffer)?;
        let packet = &buffer[..n];
        let mut buffer = InputBuffer::new(packet);
        let mut context = MacVerifier::new(&server.public_key, None);
        context.check_macs = false;
        let message = Message::decode_with_context(&mut buffer, &mut context)?;
        let kind = message.kind();
        match message {
            Message::HandshakeInitiation(message) => {
                context.check_macs = true;
                match context.verify(&mut buffer) {
                    Ok(_) => {
                        let (session, initiation, response_bytes) = Responder::respond(
                            server.public_key,
                            server.private_key.clone(),
                            &server.preshared_key,
                            message,
                        )?;
                        if let AllowedPublicKeys::Set(allowed_public_keys) =
                            &server.allowed_public_keys
                        {
                            if !allowed_public_keys.contains(&initiation.static_public) {
                                return Err(format_error!(
                                    "untrusted public key: `{}`",
                                    initiation.static_public.to_base64()
                                ));
                            }
                        }
                        server
                            .socket_addr_to_public_key
                            .insert(from, initiation.static_public);
                        // sender and receiver are flipped here
                        server
                            .session_to_destination
                            .insert((from, session.sender_index().as_u32()), server.public_key);
                        server.auth_peers.insert(
                            initiation.static_public,
                            AuthPeer {
                                session,
                                socket_addr: from,
                            },
                        );
                        eprintln!("{}->wgsr auth-peer->wgsr {:?}", from, kind);
                        server.socket.send_to(response_bytes.as_slice(), from)?;
                        eprintln!(
                            "wgsr->{} wgsr->auth-peer {:?}",
                            from,
                            MessageKind::HandshakeResponse
                        );
                    }
                    Err(e) => {
                        let from_public_key =
                            server.socket_addr_to_public_key.get(&from).ok_or_else(|| {
                                format_error!("no route for {:?} from {}: {}", kind, from, e)
                            })?;
                        if server.hub_to_spokes.contains_key(from_public_key) {
                            return Err(format_error!(
                                "handshake from `{}` failed verification: {}",
                                from_public_key.to_base64(),
                                e
                            ));
                        }
                        let to_public_key =
                            server.spoke_to_hub.get(from_public_key).ok_or_else(|| {
                                format_error!("no route for {:?} from {}", kind, from)
                            })?;
                        let to_socket_addr = server
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
                        eprintln!("{}->{} spoke->hub {:?}", from, to_socket_addr, kind);
                        server.socket.send_to(packet, to_socket_addr)?;
                        // sender and receiver are flipped here
                        server.session_to_destination.insert(
                            (to_socket_addr, message.sender_index.as_u32()),
                            *from_public_key,
                        );
                    }
                }
            }
            Message::HandshakeResponse(message) => {
                let from_public_key = server
                    .socket_addr_to_public_key
                    .get(&from)
                    .ok_or_else(|| format_error!("no route for {:?} from {}", kind, from))?;
                if !server.hub_to_spokes.contains_key(from_public_key) {
                    return Err(format_error!(
                        "received handshake response from `{}` (spoke)",
                        from_public_key.to_base64()
                    ));
                }
                let to_public_key = *server
                    .session_to_destination
                    .get(&(from, message.receiver_index.as_u32()))
                    .ok_or_else(|| {
                        format_error!(
                            "no route for {:?} from {} session {}",
                            kind,
                            from,
                            message.receiver_index
                        )
                    })?;
                let to_socket_addr = server
                    .auth_peers
                    .get(&to_public_key)
                    .ok_or_else(|| {
                        format_error!("no route for {:?} from {}: peer not authorized", kind, from)
                    })?
                    .socket_addr;
                server.socket.send_to(packet, to_socket_addr)?;
                server
                    .session_to_destination
                    .insert((from, message.receiver_index.as_u32()), to_public_key);
                server.session_to_destination.insert(
                    (to_socket_addr, message.sender_index.as_u32()),
                    *from_public_key,
                );
                eprintln!("{}->{} hub->spoke {:?}", from, to_socket_addr, kind);
            }
            Message::PacketData(message) => {
                let from_public_key = server
                    .socket_addr_to_public_key
                    .get(&from)
                    .ok_or_else(|| format_error!("no route for {:?} from {}", kind, from))?;
                let (from_kind, to_kind) = if server.hub_to_spokes.contains_key(from_public_key) {
                    ("hub", "spoke")
                } else {
                    ("spoke", "hub")
                };
                let to_public_key = server
                    .session_to_destination
                    .get(&(from, message.receiver_index.as_u32()))
                    .ok_or_else(|| {
                        format_error!(
                            "no route for {:?} from {} session {}",
                            kind,
                            from,
                            message.receiver_index
                        )
                    })?;
                if to_public_key == &server.public_key {
                    let session = &mut server
                        .auth_peers
                        .get_mut(from_public_key)
                        .ok_or_else(|| {
                            format_error!(
                                "no route for {:?} from {}: peer not authorized",
                                kind,
                                from
                            )
                        })?
                        .session;
                    let data = session.receive(&message)?;
                    if !data.is_empty() {
                        let request = RpcRequest::decode(&data)?;
                        match request.body {
                            RpcRequestBody::SetPeers(public_keys) => {
                                for public_key in public_keys.iter() {
                                    server.spoke_to_hub.insert(*public_key, *from_public_key);
                                }
                                server.hub_to_spokes.insert(*from_public_key, public_keys);
                                let response = RpcResponse {
                                    request_id: request.id,
                                    body: RpcResponseBody::SetPeers(Ok(())),
                                };
                                let mut response_bytes = Vec::new();
                                response.encode(&mut response_bytes);
                                let message = session.send(&response_bytes)?;
                                let mut buffer = Vec::new();
                                let mut signer = MacSigner::new(&server.public_key, None);
                                message.encode_with_context(&mut buffer, &mut signer);
                                server.socket.send_to(packet, from)?;
                            }
                        }
                    }
                    eprintln!("received {:?}", data);
                    eprintln!(
                        "{}->local {}->wgsr {:?}({})",
                        from,
                        from_kind,
                        kind,
                        packet.len(),
                    );
                } else {
                    let to_socket_addr = server
                        .auth_peers
                        .get(to_public_key)
                        .ok_or_else(|| {
                            format_error!(
                                "no route for {:?} from {}: peer not authorized",
                                kind,
                                from
                            )
                        })?
                        .socket_addr;
                    server.socket.send_to(packet, to_socket_addr)?;
                    eprintln!(
                        "{}->{} {}->{} {:?}({})",
                        from,
                        to_socket_addr,
                        from_kind,
                        to_kind,
                        kind,
                        packet.len(),
                    );
                }
            }
        }
        Ok(())
    }

    fn accept_unix_connections(&mut self) -> Result<(), Error> {
        use std::collections::hash_map::Entry;
        loop {
            let (mut stream, _from) = match self.unix_server.accept() {
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // no more connections to accept
                    break;
                }
                other => other,
            }?;
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
        udp_server: &mut UdpServer,
        poll: &mut Poll,
    ) -> Result<(), Error> {
        let mut interest: Option<Interest> = None;
        if event.is_readable() {
            client.fill_buf()?;
            while let Some(request) = client.read_request()? {
                let response = match request {
                    Request::Running => Response::Running,
                    Request::Status => Response::Status(Ok(Status {
                        auth_peers: udp_server
                            .auth_peers
                            .iter()
                            .map(|(k, v)| (*k, v.into()))
                            .collect(),
                        session_to_destination: Default::default(),
                        hub_to_spokes: Default::default(),
                    })),
                    Request::Export { format } => {
                        let response =
                            Self::export_config(format, udp_server).map_err(RequestError::map);
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

    fn export_config(format: ExportFormat, udp_server: &mut UdpServer) -> Result<String, Error> {
        use std::fmt::Write;
        match format {
            ExportFormat::Config => {
                let mut buf = String::with_capacity(4096);
                writeln!(&mut buf, "# wgsr authentication peer")?;
                writeln!(&mut buf, "[Peer]")?;
                writeln!(
                    &mut buf,
                    "PublicKey = {}",
                    udp_server.public_key.to_base64()
                )?;
                let mut internet_addresses = get_internet_addresses()?;
                internet_addresses.sort();
                let mut iter = internet_addresses.into_iter();
                let port = udp_server.socket.local_addr()?.port();
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
            ExportFormat::PublicKey => Ok(udp_server.public_key.to_base64()),
        }
    }
}

fn _update_config<F>(config_file: &Path, f: F) -> Result<(), Error>
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

struct UdpServer {
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
    session_to_destination: HashMap<(SocketAddr, u32), PublicKey>,
}

struct AuthPeer {
    session: Session,
    socket_addr: SocketAddr,
}

impl From<&AuthPeer> for wgsr::AuthPeer {
    fn from(other: &AuthPeer) -> Self {
        Self {
            socket_addr: other.socket_addr,
            sender_index: other.session.sender_index().as_u32(),
            receiver_index: other.session.receiver_index().as_u32(),
        }
    }
}

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

#[allow(dead_code)]
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
const UDP_SERVER_TOKEN: Token = Token(usize::MAX - 1);
const UNIX_SERVER_TOKEN: Token = Token(usize::MAX - 2);
const MAX_UNIX_CLIENTS: usize = 1000;
const UNIX_TOKEN_MAX: usize = usize::MAX - 3;
const UNIX_TOKEN_MIN: usize = UNIX_TOKEN_MAX + 1 - MAX_UNIX_CLIENTS;

const_assert!(UNIX_TOKEN_MIN <= UNIX_TOKEN_MAX);
const_assert!(UNIX_TOKEN_MAX < UNIX_SERVER_TOKEN.0);
const_assert!(UDP_SERVER_TOKEN.0 < WAKE_TOKEN.0);
const_assert!(UNIX_SERVER_TOKEN.0 < UDP_SERVER_TOKEN.0);
const_assert!(MAX_UNIX_CLIENTS == UNIX_TOKEN_MAX - UNIX_TOKEN_MIN + 1);
