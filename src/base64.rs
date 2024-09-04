use base64ct::{Base64, Encoding};
use std::fmt::Display;
use std::fmt::Formatter;
use wgproto::PrivateKey;
use wgproto::PublicKey;

#[derive(Debug)]
pub struct Base64Error;

impl std::error::Error for Base64Error {}

impl Display for Base64Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "base64 i/o error")
    }
}

pub trait FromBase64 {
    fn from_base64(other: &str) -> Result<Self, Base64Error>
    where
        Self: Sized;
}

impl FromBase64 for U8_32 {
    fn from_base64(other: &str) -> Result<Self, Base64Error> {
        let data = Base64::decode_vec(other).map_err(|_| Base64Error)?;
        data.try_into().map_err(|_| Base64Error)
    }
}

impl FromBase64 for PublicKey {
    fn from_base64(other: &str) -> Result<Self, Base64Error> {
        Ok(U8_32::from_base64(other)?.into())
    }
}

impl FromBase64 for PrivateKey {
    fn from_base64(other: &str) -> Result<Self, Base64Error> {
        Ok(U8_32::from_base64(other)?.into())
    }
}

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl ToBase64 for PublicKey {
    fn to_base64(&self) -> String {
        Base64::encode_string(self.as_bytes())
    }
}

impl ToBase64 for PrivateKey {
    fn to_base64(&self) -> String {
        Base64::encode_string(self.as_bytes())
    }
}

type U8_32 = [u8; 32];
