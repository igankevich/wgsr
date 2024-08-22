use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;

use bincode::config::Configuration;
use bincode::decode_from_slice;
use bincode::encode_into_std_write;
use bincode::error::DecodeError;
use bincode::error::EncodeError;
use bincode::Decode;
use bincode::Encode;
use serde::Deserialize;
use serde::Serialize;
use wgproto::PublicKey;

pub const DEFAULT_UNIX_SOCKET_PATH: &str = "/tmp/.wgsrd-socket";
pub const MAX_REQUEST_SIZE: usize = 4096;
pub const MAX_RESPONSE_SIZE: usize = 4096 * 16;
const MAX_SIZE: usize = const_max(MAX_RESPONSE_SIZE, MAX_REQUEST_SIZE);

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum UnixRequest {
    Running,
    Status,
    Export { format: ExportFormat },
}

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub enum UnixResponse {
    Running,
    Status(Result<Status, UnixRequestError>),
    Export(Result<String, UnixRequestError>),
}

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Status {
    #[bincode(with_serde)]
    pub auth_peers: HashMap<PublicKey, AuthPeer>,
    #[bincode(with_serde)]
    pub session_to_destination: HashMap<(SocketAddr, u32), PublicKey>,
    #[bincode(with_serde)]
    pub hub_to_spokes: HashMap<PublicKey, HashSet<PublicKey>>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct AuthPeer {
    pub socket_addr: SocketAddr,
    pub sender_index: u32,
    pub receiver_index: u32,
}

#[derive(Decode, Encode, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Peer {
    pub socket_addr: SocketAddr,
    pub session_index: u32,
    pub status: PeerStatus,
}

#[derive(PartialEq, Eq, Clone, Copy, Hash, Decode, Encode)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
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
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum ExportFormat {
    Config,
    PublicKey,
}

impl ExportFormat {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Config => "config",
            Self::PublicKey => "public-key",
        }
    }
}

impl Display for ExportFormat {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Debug for ExportFormat {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq))]
pub struct UnixRequestError(pub String);

impl UnixRequestError {
    pub fn map(other: impl ToString) -> Self {
        Self(other.to_string())
    }
}

impl Display for UnixRequestError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for UnixRequestError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for UnixRequestError {}

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
        encode_into_std_write(self, writer, bincode_config())?;
        Ok(())
    }

    fn decode<R>(reader: &mut BufReader<R>) -> Result<Self, DecodeError>
    where
        BufReader<R>: BufRead,
        R: Read,
    {
        let (object, n): (Self, usize) = decode_from_slice(reader.buffer(), bincode_config())?;
        reader.consume(n);
        Ok(object)
    }
}

const fn bincode_config() -> Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::Limit<MAX_SIZE>,
> {
    bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_SIZE>()
}

const fn const_max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use arbtest::arbtest;

    use super::*;

    #[test]
    fn response_io() {
        test_io::<UnixResponse>();
    }

    #[test]
    fn request_io() {
        test_io::<UnixRequest>();
    }

    fn test_io<T: EncodeDecode + for<'a> Arbitrary<'a> + PartialEq + Eq + Debug>() {
        arbtest(|u| {
            let expected: T = u.arbitrary()?;
            let mut buffer = Vec::with_capacity(4096);
            EncodeDecode::encode(&expected, &mut buffer).unwrap();
            let mut reader = BufReader::new(Cursor::new(buffer));
            reader.fill_buf().unwrap();
            let actual = EncodeDecode::decode(&mut reader).unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    impl<'a> Arbitrary<'a> for UnixRequest {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            let i: usize = u.int_in_range(0..=2)?;
            Ok(match i {
                0 => UnixRequest::Running,
                1 => UnixRequest::Status,
                _ => UnixRequest::Export {
                    format: u.arbitrary()?,
                },
            })
        }
    }

    impl<'a> Arbitrary<'a> for Status {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                auth_peers: u
                    .arbitrary::<HashMap<[u8; 32], AuthPeer>>()?
                    .into_iter()
                    .map(|(k, v)| (k.into(), v))
                    .collect(),
                session_to_destination: u
                    .arbitrary::<HashMap<(ArbitrarySocketAddr, u32), [u8; 32]>>()?
                    .into_iter()
                    .map(|((k0, k1), v)| ((k0.0, k1), v.into()))
                    .collect(),
                hub_to_spokes: u
                    .arbitrary::<HashMap<[u8; 32], HashSet<[u8; 32]>>>()?
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into_iter().map(Into::into).collect()))
                    .collect(),
            })
        }
    }

    impl<'a> Arbitrary<'a> for AuthPeer {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                socket_addr: u.arbitrary::<ArbitrarySocketAddr>()?.0,
                sender_index: u.arbitrary()?,
                receiver_index: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for Peer {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                socket_addr: u.arbitrary::<ArbitrarySocketAddr>()?.0,
                session_index: u.arbitrary()?,
                status: u.arbitrary()?,
            })
        }
    }

    #[derive(PartialEq, Eq, Hash)]
    struct ArbitrarySocketAddr(SocketAddr);

    impl<'a> Arbitrary<'a> for ArbitrarySocketAddr {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            let ipv4: bool = u.arbitrary()?;
            let port: u16 = u.arbitrary()?;
            Ok(Self(match ipv4 {
                true => SocketAddr::new(Ipv4Addr::from(u.arbitrary::<[u8; 4]>()?).into(), port),
                false => SocketAddr::new(Ipv6Addr::from(u.arbitrary::<[u8; 16]>()?).into(), port),
            }))
        }
    }
}
