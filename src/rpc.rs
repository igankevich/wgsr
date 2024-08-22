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

pub type RpcRequestId = u64;

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub struct RpcRequest {
    pub id: RpcRequestId,
    pub body: RpcRequestBody,
}

impl RpcRequest {
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.encode(&mut buffer);
        buffer
    }

    pub fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.id.to_le_bytes());
        self.body.encode(buffer);
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
        let id = RpcRequestId::from_le_bytes(
            buffer
                .get(..REQUEST_ID_LEN)
                .ok_or(RpcError::Other)?
                .try_into()
                .map_err(|_| RpcError::Other)?,
        );
        let body = RpcRequestBody::decode(&buffer[REQUEST_ID_LEN..])?;
        Ok(Self { id, body })
    }
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum RpcRequestBody {
    SetPeers(HashSet<PublicKey>),
}

impl RpcRequestBody {
    pub fn encode(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::SetPeers(public_keys) => {
                buffer.push(RpcKind::SetPeers as u8);
                for public_key in public_keys.iter() {
                    buffer.extend(public_key.as_bytes());
                }
            }
        }
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
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

impl RpcResponse {
    pub fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.request_id.to_le_bytes());
        self.body.encode(buffer);
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
        let request_id = RpcRequestId::from_le_bytes(
            buffer
                .get(..REQUEST_ID_LEN)
                .ok_or(RpcError::Other)?
                .try_into()
                .map_err(|_| RpcError::Other)?,
        );
        let body = RpcResponseBody::decode(&buffer[REQUEST_ID_LEN..])?;
        Ok(Self { request_id, body })
    }
}

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub enum RpcResponseBody {
    SetPeers(Result<(), RpcError>),
}

impl RpcResponseBody {
    pub fn encode(&self, buffer: &mut Vec<u8>) {
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

    pub fn decode(buffer: &[u8]) -> Result<Self, RpcError> {
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

const REQUEST_ID_LEN: usize = 8;
const PUBLIC_KEY_LEN: usize = 32;

#[cfg(test)]
mod tests {

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
        arbtest(|u| {
            let expected: RpcRequest = u.arbitrary()?;
            let mut buffer = Vec::with_capacity(4096);
            expected.encode(&mut buffer);
            let actual = RpcRequest::decode(&buffer).unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    #[test]
    fn rpc_response_io() {
        arbtest(|u| {
            let expected: RpcResponse = u.arbitrary()?;
            let mut buffer = Vec::with_capacity(4096);
            expected.encode(&mut buffer);
            let actual = RpcResponse::decode(&buffer).unwrap();
            assert_eq!(expected, actual);
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
