use std::time::Duration;

mod base64;
mod message_ext;
mod rpc;
mod unix;

pub use self::base64::*;
pub use self::message_ext::*;
pub use self::rpc::*;
pub use self::unix::*;

pub const DEFAULT_LISTEN_PORT: u16 = 8787;
pub const DEFAULT_PERSISTENT_KEEPALIVE: Duration = Duration::from_secs(23);
