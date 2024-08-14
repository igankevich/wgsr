use std::collections::HashSet;
use std::num::NonZeroU16;
use std::path::Path;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::format_error;
use crate::parse_config;
use crate::Error;
use crate::FromBase64;
use crate::ToBase64;

pub(crate) struct Config {
    pub(crate) servers: Vec<ServerConfig>,
}

impl Config {
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let mut servers: Vec<ServerConfig> = Vec::new();
        let mut prev_section: Option<String> = None;
        let mut private_key: Option<StaticSecret> = None;
        let mut preshared_key: Option<StaticSecret> = None;
        let mut public_key: Option<PublicKey> = None;
        let mut listen_port: Option<NonZeroU16> = None;
        let add_peer = |servers: &mut Vec<ServerConfig>,
                        public_key: Option<PublicKey>,
                        peer_type: PeerType|
         -> Result<(), Error> {
            match public_key {
                Some(public_key) => match servers.last_mut() {
                    None => return Err(format_error!("no servers defined")),
                    Some(server) => {
                        server.peers.push(PeerConfig {
                            public_key,
                            peer_type,
                        });
                    }
                },
                None => {
                    return Err(format_error!("missing keys: `PublicKey`"));
                }
            }
            Ok(())
        };
        let add_server = |servers: &mut Vec<ServerConfig>,
                          private_key: Option<StaticSecret>,
                          preshared_key: Option<StaticSecret>,
                          listen_port: Option<NonZeroU16>|
         -> Result<(), Error> {
            match (private_key, preshared_key, listen_port) {
                (Some(private_key), Some(preshared_key), Some(listen_port)) => {
                    servers.push(ServerConfig {
                        private_key,
                        preshared_key,
                        listen_port,
                        peers: Default::default(),
                    });
                }
                // ignore empty sections/eof
                (None, None, None) => {}
                (private_key, preshared_key, listen_port) => {
                    let mut keys: Vec<&str> = Vec::new();
                    if private_key.is_none() {
                        keys.push("`PrivateKey`");
                    }
                    if preshared_key.is_none() {
                        keys.push("`PresharedKey`");
                    }
                    if listen_port.is_none() {
                        keys.push("`ListenPort`");
                    }
                    return Err(format_error!("missing keys: {}", keys.join(", ")));
                }
            }
            Ok(())
        };
        let add = |servers: &mut Vec<ServerConfig>,
                   prev_section: Option<String>,
                   public_key: Option<PublicKey>,
                   private_key: Option<StaticSecret>,
                   preshared_key: Option<StaticSecret>,
                   listen_port: Option<NonZeroU16>|
         -> Result<(), Error> {
            match prev_section.as_deref() {
                Some("Server") => add_server(servers, private_key, preshared_key, listen_port),
                Some("Hub") => add_peer(servers, public_key, PeerType::Hub),
                Some("Spoke") => add_peer(servers, public_key, PeerType::Spoke),
                Some(other) => Err(format_error!("unknown section: {}", other)),
                // handle first section
                None => Ok(()),
            }
        };
        parse_config(path, |section, key, value, new_section| {
            eprintln!("{:?}.{} = {}", section, key, value);
            if new_section {
                add(
                    &mut servers,
                    prev_section.take(),
                    public_key.take(),
                    private_key.take(),
                    preshared_key.take(),
                    listen_port.take(),
                )?;
            }
            prev_section = section.map(ToString::to_string);
            match section {
                Some("Server") => match key {
                    "PrivateKey" => private_key = Some(FromBase64::from_base64(value)?),
                    "ListenPort" => listen_port = Some(value.parse().map_err(Error::other)?),
                    "PresharedKey" => preshared_key = Some(FromBase64::from_base64(value)?),
                    key => return Err(format_error!("unknown server key: `{}`", key)),
                },
                Some("Hub") | Some("Spoke") => match key {
                    "PublicKey" => public_key = Some(FromBase64::from_base64(value)?),
                    key => return Err(format_error!("unknown key: `{}`", key)),
                },
                Some(other) => return Err(format_error!("unknown section: {}", other)),
                None => return Err(format_error!("unknown section")),
            }
            Ok(())
        })?;
        add(
            &mut servers,
            prev_section.take(),
            public_key.take(),
            private_key.take(),
            preshared_key.take(),
            listen_port.take(),
        )?;
        validate_servers(servers.as_slice())?;
        Ok(Self { servers })
    }
}

pub(crate) struct ServerConfig {
    pub(crate) private_key: StaticSecret,
    pub(crate) preshared_key: StaticSecret,
    pub(crate) listen_port: NonZeroU16,
    pub(crate) peers: Vec<PeerConfig>,
}

pub(crate) struct PeerConfig {
    pub(crate) public_key: PublicKey,
    pub(crate) peer_type: PeerType,
}

#[derive(PartialEq, Eq)]
pub(crate) enum PeerType {
    Hub,
    Spoke,
}

impl PeerType {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Hub => "hub",
            Self::Spoke => "spoke",
        }
    }
}

fn validate_servers(servers: &[ServerConfig]) -> Result<(), Error> {
    let mut ports: HashSet<NonZeroU16> = HashSet::new();
    for server in servers.iter() {
        if !ports.insert(server.listen_port) {
            return Err(format_error!(
                "duplicate listen port: `{}`",
                server.listen_port
            ));
        }
        let public_key: PublicKey = (&server.private_key).into();
        validate_peers(server.peers.as_slice(), &public_key)?;
    }
    Ok(())
}

fn validate_peers(peers: &[PeerConfig], server_public_key: &PublicKey) -> Result<(), Error> {
    let mut public_keys: HashSet<PublicKey> = HashSet::new();
    let mut hub_found = false;
    for peer in peers.iter() {
        if peer.peer_type == PeerType::Hub {
            if hub_found {
                return Err(format_error!("only one hub per server is supported"));
            }
            hub_found = true;
        }
        if !public_keys.insert(peer.public_key) {
            return Err(format_error!(
                "duplicate public key: `{}`",
                peer.public_key.to_base64()
            ));
        }
        if &peer.public_key == server_public_key {
            return Err(format_error!(
                "peer public key is the same as server public key: `{}`",
                peer.public_key.to_base64()
            ));
        }
    }
    if !hub_found {
        return Err(format_error!("no hub found"));
    }
    Ok(())
}
