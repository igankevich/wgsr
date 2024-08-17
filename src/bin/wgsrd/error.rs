use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

pub(crate) enum Error {
    Base64,
    Other(String),
}

impl Error {
    pub(crate) fn other(message: impl ToString) -> Self {
        Self::Other(message.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Other(x) => write!(f, "{}", x),
            Self::Base64 => write!(f, "base64 i/o error"),
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
        Self::other(other)
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

#[macro_export]
macro_rules! format_error {
    ($($args:expr),*) => {
        $crate::Error::Other(format!($($args),*))
    };
}
