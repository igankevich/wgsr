use std::fmt::Display;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use wgx::DEFAULT_LISTEN_PORT;

#[derive(Clone)]
pub(crate) enum Endpoint {
    SocketAddr(SocketAddr),
    IpAddr(IpAddr),
    DnsNameWithPort(DnsNameWithPort),
    DnsName(String),
}

impl Endpoint {
    pub(crate) fn to_socket_addr(&self) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
        match self {
            Self::SocketAddr(x) => Ok(x.to_socket_addrs()?.next()),
            Self::IpAddr(x) => Ok(Some(SocketAddr::new(*x, DEFAULT_LISTEN_PORT))),
            Self::DnsNameWithPort(x) => Ok(x.name.to_socket_addrs()?.next()),
            Self::DnsName(x) => Ok(format!("{}:{}", x, DEFAULT_LISTEN_PORT)
                .to_socket_addrs()?
                .next()),
        }
    }

    pub(crate) fn into_endpoint_with_port(self) -> Self {
        match self {
            Self::IpAddr(x) => Self::SocketAddr(SocketAddr::new(x, DEFAULT_LISTEN_PORT)),
            Self::DnsName(x) => Self::DnsNameWithPort(DnsNameWithPort {
                name: format!("{}:{}", x, DEFAULT_LISTEN_PORT),
            }),
            other => other,
        }
    }
}

impl FromStr for Endpoint {
    type Err = Box<dyn std::error::Error>;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = other.parse::<SocketAddr>() {
            return Ok(Self::SocketAddr(socket_addr));
        }
        if let Ok(ipaddr) = other.parse::<IpAddr>() {
            return Ok(Self::IpAddr(ipaddr));
        }
        if let Ok(dns_name_with_port) = other.parse::<DnsNameWithPort>() {
            return Ok(Self::DnsNameWithPort(dns_name_with_port));
        }
        Ok(Self::DnsName(other.into()))
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::SocketAddr(x) => write!(f, "{}", x),
            Self::IpAddr(x) => write!(f, "{}:{}", x, DEFAULT_LISTEN_PORT),
            Self::DnsNameWithPort(x) => write!(f, "{}", x.name),
            Self::DnsName(x) => write!(f, "{}:{}", x, DEFAULT_LISTEN_PORT),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DnsNameWithPort {
    name: String,
}

impl FromStr for DnsNameWithPort {
    type Err = Box<dyn std::error::Error>;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        match other.rfind(':') {
            Some(_) => Ok(Self { name: other.into() }),
            None => Err(format!("no port in `{}`", other).into()),
        }
    }
}
