use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

pub(crate) enum Endpoint {
    SocketAddr(SocketAddr),
    IpAddr(IpAddr),
    DnsNameWithPort(DnsNameWithPort),
    DnsName(String),
}

impl Endpoint {
    pub(crate) fn to_socket_addr(
        &self,
        default_port: u16,
    ) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
        match self {
            Self::SocketAddr(x) => Ok(x.to_socket_addrs()?.next()),
            Self::IpAddr(x) => Ok(Some(SocketAddr::new(*x, default_port))),
            Self::DnsNameWithPort(x) => Ok(x.name.to_socket_addrs()?.next()),
            Self::DnsName(x) => Ok(format!("{}:{}", x, default_port).to_socket_addrs()?.next()),
        }
    }

    pub(crate) fn to_string(&self, default_port: u16) -> String {
        match self {
            Self::SocketAddr(x) => x.to_string(),
            Self::IpAddr(x) => format!("{}:{}", x, default_port),
            Self::DnsNameWithPort(x) => x.name.clone(),
            Self::DnsName(x) => format!("{}:{}", x, default_port),
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
