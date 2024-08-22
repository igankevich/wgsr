use std::collections::HashSet;

use wgproto::PublicKey;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum RpcKind {
    SetPeers = 1,
}

impl TryFrom<u8> for RpcKind {
    type Error = RpcError;
    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            1 => Ok(Self::SetPeers),
            _ => Err(RpcError::Other),
        }
    }
}

pub type RpcRequestId = u32;

impl RpcEncode for RpcRequestId {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.to_le_bytes());
    }
}

impl RpcDecode for RpcRequestId {
    fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
        let id = RpcRequestId::from_le_bytes(
            buffer
                .get(..REQUEST_ID_LEN)
                .ok_or(RpcError::Other)?
                .try_into()
                .map_err(|_| RpcError::Other)?,
        );
        Ok(id)
    }
}

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub struct RpcRequest {
    pub id: RpcRequestId,
    pub body: RpcRequestBody,
}

impl RpcEncode for RpcRequest {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.id.encode(buffer);
        self.body.encode(buffer);
    }
}

impl RpcDecode for RpcRequest {
    fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
        let id = buffer
            .get(..REQUEST_ID_LEN)
            .ok_or(RpcError::Other)?
            .decode_from()?;
        let body = buffer
            .get(REQUEST_ID_LEN..)
            .ok_or(RpcError::Other)?
            .decode_from()?;
        Ok(Self { id, body })
    }
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum RpcRequestBody {
    SetPeers(HashSet<PublicKey>),
}

impl RpcEncode for RpcRequestBody {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::SetPeers(public_keys) => {
                buffer.push(RpcKind::SetPeers as u8);
                for public_key in public_keys.iter() {
                    buffer.extend(public_key.as_bytes());
                }
            }
        }
    }
}

impl RpcDecode for RpcRequestBody {
    fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
        let kind: RpcKind = (*buffer.first().ok_or(RpcError::Other)?)
            .try_into()
            .map_err(|_| RpcError::Other)?;
        match kind {
            RpcKind::SetPeers => {
                let mut public_keys: HashSet<PublicKey> = HashSet::new();
                let mut buffer = &buffer[1..];
                while let Some(chunk) = buffer.get(..PUBLIC_KEY_LEN) {
                    let bytes: [u8; PUBLIC_KEY_LEN] =
                        chunk.try_into().map_err(|_| RpcError::Other)?;
                    public_keys.insert(bytes.into());
                    buffer = &buffer[PUBLIC_KEY_LEN..];
                }
                Ok(Self::SetPeers(public_keys))
            }
        }
    }
}

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub struct RpcResponse {
    pub request_id: RpcRequestId,
    pub body: RpcResponseBody,
}

impl RpcEncode for RpcResponse {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.request_id.encode(buffer);
        self.body.encode(buffer);
    }
}

impl RpcDecode for RpcResponse {
    fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
        let request_id = buffer
            .get(..REQUEST_ID_LEN)
            .ok_or(RpcError::Other)?
            .decode_from()?;
        let body = buffer
            .get(REQUEST_ID_LEN..)
            .ok_or(RpcError::Other)?
            .decode_from()?;
        Ok(Self { request_id, body })
    }
}

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub enum RpcResponseBody {
    SetPeers(Result<(), RpcError>),
}

impl RpcEncode for RpcResponseBody {
    fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::SetPeers(result) => {
                buffer.push(RpcKind::SetPeers as u8);
                buffer.push(match result {
                    Ok(_) => 0_u8,
                    Err(e) => *e as u8,
                });
            }
        }
    }
}

impl RpcDecode for RpcResponseBody {
    fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
        let kind: RpcKind = (*buffer.first().ok_or(RpcError::Other)?)
            .try_into()
            .map_err(|_| RpcError::Other)?;
        match kind {
            RpcKind::SetPeers => {
                let ret = *buffer.get(1).ok_or(RpcError::Other)?;
                if ret == 0 {
                    Ok(Self::SetPeers(Ok(())))
                } else {
                    Ok(Self::SetPeers(Err(ret.try_into()?)))
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum RpcError {
    Other = 1,
}

impl TryFrom<u8> for RpcError {
    type Error = RpcError;
    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            1 => Ok(Self::Other),
            _ => Err(RpcError::Other),
        }
    }
}

pub trait RpcEncode {
    fn encode(&self, buffer: &mut Vec<u8>);

    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.encode(&mut buffer);
        buffer
    }
}

pub trait RpcDecode {
    fn decode(buffer: &[u8]) -> Result<Self, RpcError>
    where
        Self: Sized;
}

pub trait RpcDecodeFrom<T> {
    fn decode_from(&self) -> Result<T, RpcError>;
}

impl<T: RpcDecode> RpcDecodeFrom<T> for &[u8] {
    fn decode_from(&self) -> Result<T, RpcError> {
        RpcDecode::decode(self)
    }
}

const REQUEST_ID_LEN: usize = 4;
const PUBLIC_KEY_LEN: usize = 32;

#[cfg(test)]
mod tests {

    use std::fmt::Debug;

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use arbtest::arbtest;

    use super::*;

    #[test]
    fn rpc_kind_io() {
        arbtest(|u| {
            let expected: RpcKind = u.arbitrary()?;
            let number = expected as u8;
            let actual: RpcKind = number.try_into().unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    #[test]
    fn rpc_request_io() {
        test_io::<RpcRequest>();
    }

    #[test]
    fn rpc_response_io() {
        test_io::<RpcResponse>();
    }

    fn test_io<T: RpcEncode + RpcDecode + for<'a> Arbitrary<'a> + PartialEq + Eq + Debug>() {
        arbtest(|u| {
            let expected: T = u.arbitrary()?;
            let mut buffer = Vec::with_capacity(4096);
            RpcEncode::encode(&expected, &mut buffer);
            let actual = RpcDecode::decode(&buffer).unwrap();
            assert_eq!(expected, actual);
            assert!(T::decode(&[]).is_err());
            Ok(())
        });
    }

    impl<'a> Arbitrary<'a> for RpcRequestBody {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self::SetPeers(
                u.arbitrary::<HashSet<[u8; PUBLIC_KEY_LEN]>>()?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ))
        }
    }
}
