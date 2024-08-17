use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::SocketAddr;

use bincode::Decode;
use bincode::Encode;
use wgproto::PublicKey;

#[derive(Decode, Encode)]
pub enum Request {
    Status,
}

#[derive(Decode, Encode)]
pub enum Response {
    Status(Result<Status, Error>),
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
    pub peer_type: PeerType,
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

#[derive(PartialEq, Eq, Clone, Copy, Hash, Decode, Encode)]
pub enum PeerType {
    Hub,
    Spoke,
}

impl PeerType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Hub => "hub",
            Self::Spoke => "spoke",
        }
    }
}
#[derive(Decode, Encode)]
pub struct Error(String);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}
