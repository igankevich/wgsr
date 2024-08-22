use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

pub enum Error {
    Io(std::io::Error),
    Other(String),
}

impl Error {
    pub fn other(message: impl ToString) -> Self {
        Self::Other(message.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Other(x) => write!(f, "{}", x),
            Self::Io(x) => write!(f, "i/o error: {}", x),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(other: std::io::Error) -> Self {
        Self::Io(other)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(other: std::fmt::Error) -> Self {
        Self::other(other)
    }
}

impl From<wgproto::Error> for Error {
    fn from(other: wgproto::Error) -> Self {
        Self::other(other)
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(other: bincode::error::DecodeError) -> Self {
        Self::other(other)
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(other: bincode::error::EncodeError) -> Self {
        Self::other(other)
    }
}

impl From<ipnet::PrefixLenError> for Error {
    fn from(other: ipnet::PrefixLenError) -> Self {
        Self::other(other)
    }
}

impl From<wgx::Base64Error> for Error {
    fn from(_other: wgx::Base64Error) -> Self {
        Self::other("base64 i/o error")
    }
}

impl From<wgx::RpcError> for Error {
    fn from(_other: wgx::RpcError) -> Self {
        Self::other("rpc error")
    }
}

#[macro_export]
macro_rules! format_error {
    ($($args:expr),*) => {
        $crate::Error::Other(format!($($args),*))
    };
}
