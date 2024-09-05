use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;
use rand::Rng;
use rand_core::OsRng;
use wgproto::PresharedKey;
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgx::parse_config;
use wgx::FromBase64;
use wgx::ToBase64;

use crate::format_error;
use crate::Endpoint;
use crate::Error;
use crate::InterfaceName;
use crate::DEFAULT_PERSISTENT_KEEPALIVE;

pub(crate) const DEFAULT_HUB_CONFIG_FILE: &str = "/etc/wgx/hub.conf";
pub(crate) const DEFAULT_SPOKE_CONFIG_FILE: &str = "/etc/wgx/spoke.conf";
type FwMark = u32;

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub(crate) struct Config {
    pub(crate) interface: InterfaceConfig,
    pub(crate) peers: Vec<PeerConfig>,
    pub(crate) interface_name: InterfaceName,
    relay: RelayConfig,
    pub(crate) file: PathBuf,
}

impl Config {
    pub(crate) fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        match Self::do_load(path) {
            Ok(mut config) => {
                config.file = path.into();
                Ok(config)
            }
            Err(e) => Err(format_error!("failed to read `{}`: {}", path.display(), e)),
        }
    }

    fn do_load(path: &Path) -> Result<Self, Error> {
        let mut config: Config = Default::default();
        let mut prev_section: Option<String> = None;
        let mut peer_public_key: Option<PublicKey> = None;
        let mut peer_preshared_key: Option<PresharedKey> = None;
        let mut peer_allowed_ips: Option<IpNet> = None;
        let mut peer_endpoint: Option<Endpoint> = None;
        let mut peer_persistent_keepalive: Option<Duration> = None;
        let add_peer = |peers: &mut Vec<PeerConfig>,
                        public_key: Option<PublicKey>,
                        preshared_key: Option<PresharedKey>,
                        allowed_ips: Option<IpNet>,
                        endpoint: Option<Endpoint>,
                        persistent_keepalive: Option<Duration>|
         -> Result<(), Error> {
            peers.push(PeerConfig {
                public_key: public_key.ok_or_else(|| format_error!("missing `PublicKey`"))?,
                preshared_key: preshared_key
                    .ok_or_else(|| format_error!("missing `PresharedKey`"))?,
                allowed_ips,
                endpoint,
                persistent_keepalive: persistent_keepalive.unwrap_or(Duration::ZERO),
            });
            Ok(())
        };
        let result = parse_config(path, |section, key, value, new_section| {
            if new_section && prev_section.as_deref() == section && section != Some("Peer") {
                return Err(format_error!("duplicate section `{}`", new_section));
            }
            if new_section {
                if prev_section.as_deref() == Some("Peer") {
                    add_peer(
                        &mut config.peers,
                        peer_public_key.take(),
                        peer_preshared_key.take(),
                        peer_allowed_ips.take(),
                        peer_endpoint.take(),
                        peer_persistent_keepalive.take(),
                    )?;
                }
                prev_section = section.map(ToString::to_string);
            }
            match section {
                Some(section @ "Hub") => match key {
                    "InterfaceName" => config.interface_name = value.parse().map_err(Error::map)?,
                    "RelayEndpoint" => {
                        config.relay.endpoint = Some(value.parse().map_err(Error::map)?)
                    }
                    "RelayPublicKey" => {
                        config.relay.public_key =
                            Some(FromBase64::from_base64(value).map_err(Error::map)?)
                    }
                    key => return Err(format_error!("unknown key under `{}`: `{}`", section, key)),
                },
                Some(section @ "Interface") => match key {
                    "ListenPort" => {
                        config.interface.listen_port = Some(value.parse().map_err(Error::map)?)
                    }
                    "FwMark" => config.interface.fwmark = value.parse().map_err(Error::map)?,
                    "PrivateKey" => {
                        config.interface.private_key =
                            FromBase64::from_base64(value).map_err(Error::map)?
                    }
                    "Address" => config.interface.address = value.parse().map_err(Error::map)?,
                    key => return Err(format_error!("unknown key under `{}`: `{}`", section, key)),
                },
                Some(section @ "Peer") => match key {
                    "PublicKey" => {
                        peer_public_key = Some(FromBase64::from_base64(value).map_err(Error::map)?)
                    }
                    "PresharedKey" => {
                        peer_preshared_key =
                            Some(FromBase64::from_base64(value).map_err(Error::map)?)
                    }
                    "AllowedIPs" => peer_allowed_ips = Some(value.parse().map_err(Error::map)?),
                    "Endpoint" => peer_endpoint = Some(value.parse().map_err(Error::map)?),
                    "PersistentKeepalive" => {
                        peer_persistent_keepalive = Some(Duration::from_secs(
                            value.parse::<u64>().map_err(Error::map)?,
                        ))
                    }
                    key => return Err(format_error!("unknown key under `{}`: `{}`", section, key)),
                },
                Some(other) => return Err(format_error!("unknown section: {}", other)),
                None => return Err(format_error!("unknown section")),
            }
            Ok(())
        });
        match result {
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
            Err(e) => return Err(e.into()),
            _ => {}
        }
        if prev_section.as_deref() == Some("Peer") {
            add_peer(
                &mut config.peers,
                peer_public_key.take(),
                peer_preshared_key.take(),
                peer_allowed_ips.take(),
                peer_endpoint.take(),
                peer_persistent_keepalive.take(),
            )?;
        }
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn save(&self) -> Result<(), Error> {
        self.save_to(self.file.as_path())
    }

    pub(crate) fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let path = path.as_ref();
        self.do_save(path)
            .map_err(|e| format_error!("failed to write `{}`: {}", path.display(), e))
    }

    fn do_save(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        if let Some(dir) = path.parent() {
            create_dir_all(dir)?;
        }
        let mut file = File::create(path)?;
        write!(&mut file, "{}", self)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.interface_name.0.is_empty() {
            return Err(format_error!(
                "invalid interface name: `{}`",
                self.interface_name
            ));
        }
        let mut public_keys: HashSet<PublicKey> = HashSet::new();
        let mut addresses: HashSet<IpNet> = HashSet::new();
        public_keys.insert((&self.interface.private_key).into());
        addresses.insert(self.interface.address);
        for peer in self.peers.iter() {
            if !public_keys.insert(peer.public_key) {
                return Err(format_error!(
                    "duplicate public key: {}",
                    peer.public_key.to_base64()
                ));
            }
            if let Some(allowed_ips) = peer.allowed_ips {
                if !addresses.insert(allowed_ips) {
                    return Err(format_error!("duplicate IP address: {}", allowed_ips));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::unwrap_used)]
    pub(crate) fn random_ip_address(&self) -> Result<IpNet, Error> {
        let mut addresses: HashSet<IpAddr> = HashSet::new();
        addresses.insert(self.interface.address.addr());
        addresses.extend(
            self.peers
                .iter()
                .filter_map(|peer| peer.allowed_ips.map(|x| x.addr())),
        );
        let n = self.interface.address.hosts().count();
        if n == addresses.len() {
            return Err(format_error!("exhausted available IP addresses"));
        }
        loop {
            let i = OsRng.gen_range(0..n);
            let address = match self.interface.address.hosts().nth(i) {
                Some(address) => address,
                None => continue,
            };
            if !addresses.contains(&address) {
                return Ok(IpNet::new(address, self.interface.address.prefix_len()).unwrap());
            }
        }
    }

    pub(crate) fn get_relay_endpoint(&self) -> Result<&Endpoint, Error> {
        self.relay
            .endpoint
            .as_ref()
            .ok_or_else(|| format_error!("no `Relay` is specified in `{}`", self.file.display()))
    }

    pub(crate) fn set_relay(
        &mut self,
        endpoint: Option<Endpoint>,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        if endpoint.is_some() {
            self.peers.retain(|peer| peer.public_key != public_key);
            self.peers.push(PeerConfig {
                public_key,
                preshared_key: [0_u8; 32].into(),
                allowed_ips: Some(self.random_ip_address()?),
                endpoint: endpoint.clone(),
                persistent_keepalive: DEFAULT_PERSISTENT_KEEPALIVE,
            });
        }
        self.relay = RelayConfig {
            endpoint,
            public_key: Some(public_key),
        };
        Ok(())
    }

    pub(crate) fn get_relay_public_key(&self) -> Option<&PublicKey> {
        self.relay.public_key.as_ref()
    }

    pub(crate) fn get_relay_ip_addr_and_peers_public_keys(
        &self,
    ) -> Result<(IpAddr, HashSet<PublicKey>), Error> {
        let relay_public_key = self
            .relay
            .public_key
            .ok_or_else(|| format_error!("no relay public key"))?;
        let mut relay_ip_addr: Option<IpAddr> = None;
        let mut public_keys: HashSet<PublicKey> = HashSet::new();
        for peer in self.peers.iter() {
            if peer.public_key == relay_public_key {
                relay_ip_addr = Some(
                    peer.allowed_ips
                        .ok_or_else(|| format_error!("no allowed ips for relay peer"))?
                        .addr(),
                );
            } else {
                public_keys.insert(peer.public_key);
            }
        }
        Ok((
            relay_ip_addr.ok_or_else(|| format_error!("relay peer not found"))?,
            public_keys,
        ))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface_name: InterfaceName("wgx".into()),
            relay: RelayConfig {
                endpoint: None,
                public_key: None,
            },
            interface: InterfaceConfig {
                private_key: PrivateKey::random(),
                address: default_interface_address(),
                fwmark: 0,
                listen_port: None,
            },
            peers: Default::default(),
            file: Default::default(),
        }
    }
}

#[allow(clippy::unwrap_used)]
fn default_interface_address() -> IpNet {
    IpNet::new(Ipv4Addr::new(10, 120, 0, 1).into(), 16).unwrap()
}

#[allow(clippy::unwrap_used)]
pub(crate) fn allowed_ip_any() -> IpNet {
    IpNet::new(Ipv4Addr::UNSPECIFIED.into(), 0).unwrap()
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "[Hub]")?;
        writeln!(f, "InterfaceName = {}", self.interface_name)?;
        if let Some(relay_endpoint) = self.relay.endpoint.as_ref() {
            writeln!(f, "RelayEndpoint = {}", relay_endpoint)?;
        }
        if let Some(relay_public_key) = self.relay.public_key.as_ref() {
            writeln!(f, "RelayPublicKey = {}", relay_public_key.to_base64())?;
        }
        writeln!(f)?;
        writeln!(f, "{}", self.interface)?;
        for peer in self.peers.iter() {
            writeln!(f, "{}", peer)?;
        }
        Ok(())
    }
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
struct RelayConfig {
    endpoint: Option<Endpoint>,
    public_key: Option<PublicKey>,
}

pub(crate) struct InterfaceConfig {
    pub(crate) private_key: PrivateKey,
    pub(crate) address: IpNet,
    pub(crate) fwmark: FwMark,
    pub(crate) listen_port: Option<NonZeroU16>,
}

impl InterfaceConfig {
    pub(crate) fn write_wireguard_config(&self, out: &mut impl Write) -> Result<(), Error> {
        writeln!(out, "[Interface]")?;
        writeln!(out, "PrivateKey = {}", self.private_key.to_base64())?;
        if let Some(listen_port) = self.listen_port {
            writeln!(out, "ListenPort = {}", listen_port)?;
        }
        if self.fwmark != 0 {
            writeln!(out, "FwMark = {}", self.fwmark)?;
        }
        Ok(())
    }
}

impl Display for InterfaceConfig {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "[Interface]")?;
        writeln!(f, "PrivateKey = {}", self.private_key.to_base64())?;
        if let Some(listen_port) = self.listen_port {
            writeln!(f, "ListenPort = {}", listen_port)?;
        }
        writeln!(f, "Address = {}", self.address)?;
        if self.fwmark != 0 {
            writeln!(f, "FwMark = {}", self.fwmark)?;
        }
        Ok(())
    }
}

pub(crate) struct PeerConfig {
    pub(crate) public_key: PublicKey,
    pub(crate) preshared_key: PresharedKey,
    pub(crate) allowed_ips: Option<IpNet>,
    pub(crate) endpoint: Option<Endpoint>,
    pub(crate) persistent_keepalive: Duration,
}

impl PeerConfig {
    pub(crate) fn write_wireguard_config(&self, out: &mut impl Write) -> Result<(), Error> {
        writeln!(out, "[Peer]")?;
        writeln!(out, "PublicKey = {}", self.public_key.to_base64())?;
        if self.preshared_key.as_bytes().iter().any(|b| b != &0) {
            writeln!(out, "PresharedKey = {}", self.preshared_key.to_base64())?;
        }
        if let Some(allowed_ips) = self.allowed_ips {
            writeln!(out, "AllowedIPs = {}", allowed_ips)?;
        }
        if let Some(endpoint) = self.endpoint.as_ref() {
            writeln!(out, "Endpoint = {}", endpoint.to_endpoint_with_port())?;
        }
        if self.persistent_keepalive != Duration::ZERO {
            writeln!(
                out,
                "PersistentKeepalive = {}",
                self.persistent_keepalive.as_secs()
            )?;
        }
        Ok(())
    }
}

impl Display for PeerConfig {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "[Peer]")?;
        writeln!(f, "PublicKey = {}", self.public_key.to_base64())?;
        writeln!(f, "PresharedKey = {}", self.preshared_key.to_base64())?;
        if let Some(allowed_ips) = self.allowed_ips {
            writeln!(f, "AllowedIPs = {}", allowed_ips)?;
        }
        if let Some(endpoint) = self.endpoint.as_ref() {
            writeln!(f, "Endpoint = {}", endpoint)?;
        }
        if self.persistent_keepalive != Duration::ZERO {
            writeln!(
                f,
                "PersistentKeepalive = {}",
                self.persistent_keepalive.as_secs()
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use arbtest::arbtest;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn save_load() {
        arbtest(|u| {
            let expected: Config = u.arbitrary()?;
            let file = NamedTempFile::new().unwrap();
            expected.save_to(file.path()).unwrap();
            let actual = Config::load(file.path()).unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    impl<'a> Arbitrary<'a> for Config {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                interface_name: u.arbitrary()?,
                relay: u.arbitrary()?,
                interface: u.arbitrary()?,
                peers: u.arbitrary()?,
                file: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for RelayConfig {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                public_key: u.arbitrary::<Option<[u8; 32]>>()?.map(Into::into),
                endpoint: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for InterfaceConfig {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                private_key: u.arbitrary::<[u8; 32]>()?.into(),
                address: arbitrary_ip_net(u)?,
                fwmark: u.arbitrary()?,
                listen_port: u.arbitrary()?,
            })
        }
    }

    impl Debug for InterfaceConfig {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            f.debug_struct("InterfaceConfig")
                .field("private_key", &self.private_key.to_base64())
                .field("address", &self.address)
                .field("fwmark", &self.fwmark)
                .field("listen_port", &self.listen_port)
                .finish()
        }
    }

    impl PartialEq for InterfaceConfig {
        fn eq(&self, other: &Self) -> bool {
            self.private_key.as_bytes() == other.private_key.as_bytes()
                && self.address == other.address
                && self.fwmark == other.fwmark
                && self.listen_port == other.listen_port
        }
    }

    impl Eq for InterfaceConfig {}

    impl<'a> Arbitrary<'a> for PeerConfig {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                public_key: u.arbitrary::<[u8; 32]>()?.into(),
                preshared_key: u.arbitrary::<[u8; 32]>()?.into(),
                allowed_ips: u.arbitrary::<Option<ArbitraryIpNet>>()?.map(|x| x.0),
                endpoint: u.arbitrary()?,
                persistent_keepalive: Duration::from_secs(u.arbitrary()?),
            })
        }
    }

    impl Debug for PeerConfig {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            f.debug_struct("PeerConfig")
                .field("public_key", &self.public_key.to_base64())
                .field("preshared_key", &self.preshared_key.to_base64())
                .field("allowed_ips", &self.allowed_ips)
                .field("endpoint", &self.endpoint)
                .field("persistent_keepalive", &self.persistent_keepalive)
                .finish()
        }
    }

    impl PartialEq for PeerConfig {
        fn eq(&self, other: &Self) -> bool {
            self.public_key.as_bytes() == other.public_key.as_bytes()
                && self.preshared_key.as_bytes() == other.preshared_key.as_bytes()
                && self.allowed_ips == other.allowed_ips
                && self.endpoint == other.endpoint
                && self.persistent_keepalive == other.persistent_keepalive
        }
    }

    impl Eq for PeerConfig {}

    #[derive(Debug)]
    struct ArbitraryIpNet(IpNet);

    impl<'a> Arbitrary<'a> for ArbitraryIpNet {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self(arbitrary_ip_net(u)?))
        }
    }

    fn arbitrary_ip_net(u: &mut Unstructured<'_>) -> Result<IpNet, arbitrary::Error> {
        let ipaddr: IpAddr = u.arbitrary()?;
        let max_prefix_len = match ipaddr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = u.int_in_range(0..=max_prefix_len)?;
        Ok(IpNet::new(ipaddr, prefix_len).unwrap())
    }
}
