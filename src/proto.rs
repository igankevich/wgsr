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
use wgproto::PublicKey;

pub const DEFAULT_UNIX_SOCKET_PATH: &str = "/tmp/.wgsrd-socket";
pub const MAX_REQUEST_SIZE: usize = 4096;
pub const MAX_RESPONSE_SIZE: usize = 4096 * 16;
const MAX_SIZE: usize = const_max(MAX_RESPONSE_SIZE, MAX_REQUEST_SIZE);

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum Request {
    Running,
    Status,
    Export { format: ExportFormat },
}

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum Response {
    Running,
    Status(Result<Status, RequestError>),
    Export(Result<String, RequestError>),
}

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Status {
    pub auth_peers: Vec<AuthPeer>,
    pub peers: Vec<Peer>,
    #[bincode(with_serde)]
    pub routes: HashMap<PublicKey, HashSet<PublicKey>>,
}

#[derive(Decode, Encode)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct AuthPeer {
    pub socket_addr: SocketAddr,
    #[bincode(with_serde)]
    pub public_key: PublicKey,
    pub session_index: u32,
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
        // TODO
        //test_io::<Response>();
    }

    #[test]
    fn request_io() {
        test_io::<Request>();
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

    impl<'a> Arbitrary<'a> for Request {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            let i: usize = u.int_in_range(0..=2)?;
            Ok(match i {
                0 => Request::Running,
                1 => Request::Status,
                _ => Request::Export {
                    format: u.arbitrary()?,
                },
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
