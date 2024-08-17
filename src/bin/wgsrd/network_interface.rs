use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use ipnet::IpNet;
use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;

use crate::Error;

pub(crate) fn get_internet_addresses() -> Result<Vec<IpAddr>, Error> {
    let mut internet_addresses = Vec::new();
    let network_interfaces = NetworkInterface::show().map_err(Error::other)?;
    let private_networks = get_private_networks()?;
    for iface in network_interfaces.into_iter() {
        for addr in iface.addr.into_iter() {
            let ipnet: IpNet = match addr {
                network_interface::Addr::V4(addr) => {
                    Ipv4Net::with_netmask(addr.ip, addr.netmask.unwrap_or(Ipv4Addr::BROADCAST))?
                        .into()
                }
                network_interface::Addr::V6(addr) => Ipv6Net::with_netmask(
                    addr.ip,
                    addr.netmask
                        .unwrap_or(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)),
                )?
                .into(),
            };
            if !private_networks.iter().any(|n| ipnet.is_sibling(n)) {
                internet_addresses.push(ipnet.addr());
            }
        }
    }
    Ok(internet_addresses)
}

fn get_private_networks() -> Result<[IpNet; 6], Error> {
    Ok([
        Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8)?.into(),
        Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 0), 12)?.into(),
        Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16)?.into(),
        Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)?.into(),
        // link-local
        Ipv6Net::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10)?.into(),
        // unique local addresses
        Ipv6Net::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 8)?.into(),
    ])
}
