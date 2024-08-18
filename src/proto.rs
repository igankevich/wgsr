use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::num::NonZeroU16;

use bincode::decode_from_slice;
use bincode::encode_into_std_write;
use bincode::error::DecodeError;
use bincode::error::EncodeError;
use bincode::Decode;
use bincode::Encode;
use wgproto::PublicKey;

pub const DEFAULT_UNIX_SOCKET_PATH: &str = "/tmp/.wgsrd-socket";
pub const MAX_REQUEST_SIZE: usize = 4096;
pub const MAX_RESPONSE_SIZE: usize = 4096 * 16;

#[derive(Decode, Encode)]
pub enum Request {
    Status,
    RelayAdd {
        listen_port: Option<NonZeroU16>,
        persistent: bool,
    },
    RelayRemove {
        listen_port: NonZeroU16,
        persistent: bool,
    },
    HubAdd {
        listen_port: NonZeroU16,
        #[bincode(with_serde)]
        public_key: PublicKey,
        persistent: bool,
    },
    HubRemove {
        listen_port: NonZeroU16,
        #[bincode(with_serde)]
        public_key: PublicKey,
        persistent: bool,
    },
    SpokeAdd {
        listen_port: NonZeroU16,
        #[bincode(with_serde)]
        public_key: PublicKey,
        persistent: bool,
    },
    SpokeRemove {
        listen_port: NonZeroU16,
        #[bincode(with_serde)]
        public_key: PublicKey,
        persistent: bool,
    },
    Export {
        listen_port: NonZeroU16,
    },
}

#[derive(Decode, Encode)]
pub enum Response {
    Status(Result<Status, RequestError>),
    RelayAdd(Result<NonZeroU16, RequestError>),
    RelayRemove(Result<(), RequestError>),
    HubAdd(Result<(), RequestError>),
    HubRemove(Result<(), RequestError>),
    SpokeAdd(Result<(), RequestError>),
    SpokeRemove(Result<(), RequestError>),
    Export(Result<String, RequestError>),
}

#[derive(Decode, Encode)]
pub struct Status {
    pub servers: Vec<Server>,
}

#[derive(Decode, Encode)]
pub struct Server {
    pub socket_addr: SocketAddr,
    pub hub: Option<Hub>,
    pub spokes: Vec<Spoke>,
    pub peers: Vec<Peer>,
}

#[derive(Decode, Encode)]
pub struct Hub {
    pub socket_addr: SocketAddr,
    #[bincode(with_serde)]
    pub public_key: PublicKey,
    pub session_index: u32,
}

pub type Spoke = Hub;

#[derive(Decode, Encode, Clone)]
pub struct Peer {
    pub socket_addr: SocketAddr,
    pub session_index: u32,
    pub status: PeerStatus,
    pub kind: PeerKind,
}

#[derive(PartialEq, Eq, Clone, Copy, Hash, Decode, Encode)]
pub enum PeerStatus {
    Pending,
    Authorized,
}

impl PeerStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
        }
    }
}

impl Display for PeerStatus {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Debug for PeerStatus {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Hash, Decode, Encode)]
pub enum PeerKind {
    Hub,
    Spoke,
}

impl PeerKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Hub => "hub",
            Self::Spoke => "spoke",
        }
    }
}

impl Display for PeerKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Debug for PeerKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(Decode, Encode)]
pub struct RequestError(pub String);

impl RequestError {
    pub fn map(other: impl ToString) -> Self {
        Self(other.to_string())
    }
}

impl Display for RequestError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for RequestError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for RequestError {}

pub trait EncodeDecode {
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodeError>;
    fn decode<R>(reader: &mut BufReader<R>) -> Result<Self, DecodeError>
    where
        Self: Sized,
        BufReader<R>: BufRead,
        R: Read;
}

impl<T: Encode + Decode> EncodeDecode for T {
    fn encode(&self, writer: &mut impl Write) -> Result<(), EncodeError> {
        encode_into_std_write(self, writer, bincode::config::standard())?;
        Ok(())
    }

    fn decode<R>(reader: &mut BufReader<R>) -> Result<Self, DecodeError>
    where
        BufReader<R>: BufRead,
        R: Read,
    {
        let (object, n): (Self, usize) =
            decode_from_slice(reader.buffer(), bincode::config::standard())?;
        reader.consume(n);
        Ok(object)
    }
}
