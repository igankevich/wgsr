use std::collections::HashSet;

use wgproto::PublicKey;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
                for window in buffer[1..].windows(PUBLIC_KEY_LEN) {
                    let bytes: [u8; PUBLIC_KEY_LEN] =
                        window.try_into().map_err(|_| RpcError::Other)?;
                    public_keys.insert(bytes.into());
                }
                Ok(Self::SetPeers(public_keys))
            }
        }
    }
}

pub struct RpcResponse {
    pub request_id: RpcRequestId,
    pub body: RpcResponseBody,
}

impl RpcResponse {
    pub fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.request_id.to_le_bytes());
        self.body.encode(buffer);
    }
}

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
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum RpcError {
    Other = 1,
}

const REQUEST_ID_LEN: usize = 8;
const PUBLIC_KEY_LEN: usize = 32;
