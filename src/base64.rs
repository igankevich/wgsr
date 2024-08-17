use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use wgproto::PrivateKey;
use wgproto::PublicKey;

use crate::Error;

pub trait FromBase64 {
    fn from_base64(other: &str) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FromBase64 for U8_32 {
    fn from_base64(other: &str) -> Result<Self, Error> {
        let data = BASE64_ENGINE.decode(other).map_err(|_| Error::Base64)?;
        data.try_into().map_err(|_| Error::Base64)
    }
}

impl FromBase64 for PublicKey {
    fn from_base64(other: &str) -> Result<Self, Error> {
        Ok(U8_32::from_base64(other)?.into())
    }
}

impl FromBase64 for PrivateKey {
    fn from_base64(other: &str) -> Result<Self, Error> {
        Ok(U8_32::from_base64(other)?.into())
    }
}

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl ToBase64 for PublicKey {
    fn to_base64(&self) -> String {
        BASE64_ENGINE.encode(self.as_bytes())
    }
}

impl ToBase64 for PrivateKey {
    fn to_base64(&self) -> String {
        BASE64_ENGINE.encode(self.as_bytes())
    }
}

type U8_32 = [u8; 32];
