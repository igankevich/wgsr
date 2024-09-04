use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::process::Command;
use std::process::Stdio;

use ipnet::IpNet;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::ToBase64;
use wgx::DEFAULT_PERSISTENT_KEEPALIVE;

use crate::format_error;
use crate::ChildHR;
use crate::CommandHR;
use crate::Error;
use crate::InterfaceConfig;
use crate::PeerConfig;

pub(crate) struct Wg {
    name: String,
}

impl Wg {
    pub(crate) fn new(name: String) -> Self {
        Self { name }
    }

    pub(crate) fn start(
        &self,
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<(), Error> {
        self.ip_link_add()?;
        self.ip_link_set_up()?;
        self.ip_address_add(interface)?;
        self.ip_route_add(interface)?;
        self.wg_conf("setconf", interface, peers)?;
        Ok(())
    }

    pub(crate) fn reload(
        &self,
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<(), Error> {
        self.ip_address_flush()?;
        self.ip_address_add(interface)?;
        self.ip_route_flush()?;
        self.ip_route_add(interface)?;
        self.wg_conf("syncconf", interface, peers)?;
        Ok(())
    }

    pub(crate) fn stop(&self) -> Result<(), Error> {
        self.ip_link_delete()?;
        Ok(())
    }

    fn ip_link_add(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["link", "add", self.name.as_str(), "type", "wireguard"])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_link_delete(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["link", "delete", self.name.as_str()])
            .status_silent_hr()?;
        Ok(())
    }

    fn ip_link_set_up(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["link", "set", self.name.as_str(), "up"])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_address_add(&self, interface: &InterfaceConfig) -> Result<(), Error> {
        Command::new("ip")
            .args([
                "address",
                "add",
                interface.address.to_string().as_str(),
                "dev",
                self.name.as_str(),
            ])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_address_flush(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["address", "flush", "dev", self.name.as_str()])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_route_add(&self, interface: &InterfaceConfig) -> Result<(), Error> {
        Command::new("ip")
            .args([
                "route",
                "add",
                interface.address.network().to_string().as_str(),
                "dev",
                self.name.as_str(),
            ])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_route_flush(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["route", "flush", "dev", self.name.as_str()])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn wg_conf(
        &self,
        verb: &str,
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<(), Error> {
        let mut command = Command::new("wg");
        command.args([verb, self.name.as_str(), "/dev/stdin"]);
        command.stdin(Stdio::piped());
        let mut child = command.spawn_hr()?;
        if let Some(mut stdin) = child.stdin.take() {
            interface.write_wireguard_config(&mut stdin)?;
            for peer in peers.iter() {
                peer.write_wireguard_config(&mut stdin)?;
            }
        }
        child.wait_hr(&command)?;
        Ok(())
    }
}

pub(crate) fn get_relay_ip_addr_and_peers_public_keys(
    wg_interface: &str,
    relay_public_key: &PublicKey,
    relay_socket_addr: SocketAddr,
) -> Result<(IpAddr, HashSet<PublicKey>), Error> {
    let output = Command::new("wg")
        .args(["show", wg_interface, "allowed-ips"])
        .stdin(Stdio::null())
        .output_hr()?;
    let output = String::from_utf8(output.stdout).map_err(Error::map)?;
    let mut public_keys: HashSet<PublicKey> = HashSet::new();
    let mut relay_ip_addr: Option<IpAddr> = None;
    for line in output.lines() {
        let mut iter = line.split('\t');
        let public_key = iter
            .next()
            .ok_or_else(|| format_error!("invalid wg line: `{}`", line))?;
        let allowed_ips = iter
            .next()
            .ok_or_else(|| format_error!("invalid wg line: `{}`", line))?;
        let public_key = PublicKey::from_base64(public_key).map_err(Error::map)?;
        if &public_key == relay_public_key {
            let ipnet: IpNet = allowed_ips.parse().map_err(Error::map)?;
            relay_ip_addr = Some(ipnet.network());
        } else {
            public_keys.insert(public_key);
        }
    }
    let inner_ip_addr_str = format!("{}/32", DEFAULT_RELAY_INNER_IP_ADDR);
    let relay_ip_addr: IpAddr = match relay_ip_addr {
        None => {
            Command::new("wg")
                .args([
                    "set",
                    wg_interface,
                    "peer",
                    relay_public_key.to_base64().as_str(),
                    "endpoint",
                    relay_socket_addr.to_string().as_str(),
                    "allowed-ips",
                    inner_ip_addr_str.as_str(),
                    "persistent-keepalive",
                    DEFAULT_PERSISTENT_KEEPALIVE.as_secs().to_string().as_str(),
                ])
                .status_hr()?;
            DEFAULT_RELAY_INNER_IP_ADDR.into()
        }
        Some(relay_ip_addr) => relay_ip_addr,
    };
    Command::new("ip")
        .args([
            "route",
            "add",
            inner_ip_addr_str.as_str(),
            "dev",
            wg_interface,
        ])
        .status_silent_hr()?;
    Ok((relay_ip_addr, public_keys))
}

const DEFAULT_RELAY_INNER_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 107, 111, 116);
