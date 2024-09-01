use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Output;
use std::process::Stdio;

use ipnet::IpNet;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::ToBase64;
use wgx::DEFAULT_PERSISTENT_KEEPALIVE;

use crate::format_error;
use crate::Error;

pub(crate) fn get_wg_public_key(wg_interface: &str) -> Result<PublicKey, Error> {
    let output = Command::new("wg")
        .args(["show", wg_interface, "public-key"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format_error!("failed to execute `wg`: {}", e))?;
    check_status(&output, "wg")?;
    let output = String::from_utf8(output.stdout).map_err(Error::map)?;
    FromBase64::from_base64(output.trim()).map_err(Error::map)
}

pub(crate) fn get_relay_ip_addr_and_peers_public_keys(
    wg_interface: &str,
    relay_public_key: &PublicKey,
    relay_socket_addr: SocketAddr,
) -> Result<(IpAddr, HashSet<PublicKey>), Error> {
    let output = Command::new("wg")
        .args(["show", wg_interface, "allowed-ips"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format_error!("failed to execute `wg`: {}", e))?;
    check_status(&output, "wg")?;
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
            let status = Command::new("wg")
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
                .status()
                .map_err(|e| format_error!("failed to execute `wg`: {}", e))?;
            if !status.success() {
                return Err(format_error!("`wg` failed: {}", status_to_string(status)));
            }
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
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .status()?;
    Ok((relay_ip_addr, public_keys))
}

fn check_status(output: &Output, command: &str) -> Result<(), Error> {
    if !output.status.success() {
        Err(format_error!(
            "`{}` failed: {}: {}",
            command,
            status_to_string(output.status),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    } else {
        Ok(())
    }
}

fn status_to_string(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exited with status code {}", code),
        None => "terminated by signal".to_string(),
    }
}

const DEFAULT_RELAY_INNER_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 107, 111, 116);
