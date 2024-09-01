use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

pub struct Error(pub String);

impl Error {
    pub fn map(other: impl ToString) -> Self {
        Self(other.to_string())
    }
}

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

impl From<std::io::Error> for Error {
    fn from(other: std::io::Error) -> Self {
        Self(other.to_string())
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(other: bincode::error::DecodeError) -> Self {
        Self(other.to_string())
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(other: bincode::error::EncodeError) -> Self {
        Self(other.to_string())
    }
}

#[macro_export]
macro_rules! format_error {
    ($($args:expr),*) => {
        $crate::Error(format!($($args),*))
    };
}
