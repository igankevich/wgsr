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

#[macro_export]
macro_rules! format_error {
    ($($args:expr),*) => {
        ::std::io::Error::new(::std::io::ErrorKind::Other, format!($($args),*))
    };
}

pub(crate) fn get_relay_ip_addr_and_peers_public_keys(
    wg_interface: &str,
    relay_public_key: &PublicKey,
    relay_socket_addr: SocketAddr,
) -> Result<(IpAddr, HashSet<PublicKey>), std::io::Error> {
    let output = Command::new("wg")
        .args(["show", wg_interface, "allowed-ips"])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(format_error!(
            "wg failed with status {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let output =
        String::from_utf8(output.stdout).map_err(|e| format_error!("utf-8 error: {}", e))?;
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
        let public_key =
            PublicKey::from_base64(public_key).map_err(|_| format_error!("base64 i/o error"))?;
        if &public_key == relay_public_key {
            let ipnet: IpNet = allowed_ips.parse().map_err(|e| format_error!("{}", e))?;
            relay_ip_addr = Some(ipnet.network());
        } else {
            public_keys.insert(public_key);
        }
    }
    let relay_ip_addr: IpAddr = match relay_ip_addr {
        None => {
            let status = Command::new("wg")
                .args([
                    "set",
                    wg_interface,
                    "peer",
                    relay_public_key.to_base64().as_str(),
                    "endpoint",
                    relay_socket_addr.to_string().as_str(),
                    "allowed-ips",
                    format!("{}/32", DEFAULT_RELAY_INNER_IP_ADDR).as_str(),
                ])
                .status()?;
            if !status.success() {
                return Err(format_error!("wg failed with status {:?}", status));
            }
            DEFAULT_RELAY_INNER_IP_ADDR.into()
        }
        Some(relay_ip_addr) => relay_ip_addr,
    };
    Ok((relay_ip_addr, public_keys))
}

const DEFAULT_RELAY_INNER_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 107, 111, 116);
