use std::fmt::Display;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use wgx::DEFAULT_LISTEN_PORT;

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
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

    pub(crate) fn to_endpoint_with_port(&self) -> Self {
        match self {
            Self::SocketAddr(x) => Self::SocketAddr(*x),
            Self::IpAddr(x) => Self::SocketAddr(SocketAddr::new(*x, DEFAULT_LISTEN_PORT)),
            Self::DnsNameWithPort(x) => Self::DnsNameWithPort(x.clone()),
            Self::DnsName(x) => Self::DnsNameWithPort(DnsNameWithPort {
                name: format!("{}:{}", x, DEFAULT_LISTEN_PORT),
            }),
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
            Self::IpAddr(x) => write!(f, "{}", x),
            Self::DnsNameWithPort(x) => write!(f, "{}", x.name),
            Self::DnsName(x) => write!(f, "{}", x),
        }
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug, arbitrary::Arbitrary))]
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

#[cfg(test)]
mod tests {

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;

    use super::*;

    impl<'a> Arbitrary<'a> for Endpoint {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            let i = u.int_in_range(0..=3)?;
            Ok(match i {
                0 => Self::SocketAddr(SocketAddr::new(u.arbitrary()?, u.arbitrary()?)),
                1 => Self::IpAddr(u.arbitrary()?),
                2 => Self::DnsNameWithPort(DnsNameWithPort {
                    name: format!("{}:{}", arbitrary_dns_name(u)?, u.arbitrary::<u16>()?),
                }),
                _ => Self::DnsName(arbitrary_dns_name(u)?),
            })
        }
    }

    fn arbitrary_dns_name(u: &mut Unstructured<'_>) -> Result<String, arbitrary::Error> {
        let len = u.arbitrary_len::<char>()?.max(1);
        let mut name = String::with_capacity(len);
        for _ in 0..len {
            name.push(char::from_u32(u.int_in_range(('a' as u32)..=('z' as u32))?).unwrap());
        }
        Ok(name)
    }
}
