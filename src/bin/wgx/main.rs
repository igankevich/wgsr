use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use std::time::SystemTime;

use clap::CommandFactory;
use clap::Parser;
use clap::Subcommand;
use colored::Colorize;
use ipnet::IpNet;
use qrencode::EcLevel;
use qrencode::QrCode;
use wgproto::PresharedKey;
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::Routes;
use wgx::Sessions;
use wgx::Status;
use wgx::ToBase64;
use wgx::UnixRequest;
use wgx::UnixResponse;
use wgx::DEFAULT_PERSISTENT_KEEPALIVE;
use wgx::DEFAULT_UNIX_SOCKET_PATH;

use self::command_hr::*;
use self::config::*;
use self::endpoint::*;
use self::error::*;
use self::interface_name::*;
use self::qrcode::*;
use self::units::*;
use self::unix::*;
use self::wg::*;
use self::wgx_client::*;

mod command_hr;
mod config;
mod endpoint;
mod error;
mod interface_name;
mod qrcode;
mod units;
mod unix;
mod wg;
mod wgx_client;

#[derive(Parser)]
#[command(
    about = "Wireguard Relay Extensions.",
    long_about = None,
    trailing_var_arg = true,
)]
struct Args {
    /// Print version.
    #[clap(long, action)]
    version: bool,
    /// UNIX socket path.
    #[arg(
        short = 's',
        long = "unix",
        value_name = "path",
        default_value = DEFAULT_UNIX_SOCKET_PATH
    )]
    unix_socket_path: PathBuf,
    /// Subcommand to run.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Relay commands.
    #[command(subcommand)]
    Relay(RelayCommand),
    /// Hub commands.
    Hub {
        /// Hub configuration file.
        #[arg(
            short = 'c',
            long = "config",
            value_name = "path",
            default_value = DEFAULT_HUB_CONFIG_FILE,
        )]
        config_file: PathBuf,
        #[command(subcommand)]
        command: HubCommand,
    },
    /// Spoke commands.
    Spoke {
        /// Spoke configuration file.
        #[arg(
            short = 'c',
            long = "config",
            value_name = "path",
            default_value = DEFAULT_SPOKE_CONFIG_FILE,
        )]
        config_file: PathBuf,
        #[command(subcommand)]
        command: SpokeCommand,
    },
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Check if wgx daemon is running.
    Running,
    /// Get relay status.
    Status,
    /// Get routing table.
    #[clap(alias = "route")]
    Routes,
    /// Get session table.
    Sessions,
    /// Get relay's public key.
    PublicKey,
    /// Export hub configuration.
    Export,
}

#[derive(Subcommand)]
enum HubCommand {
    /// Generate hub configuration.
    Init {
        /// Relay's endpoint.
        #[arg(value_name = "IP[:PORT]")]
        relay: String,
    },
    /// Add new spoke to the hub.
    AddSpoke {
        /// Export as QR-code.
        #[clap(long, action)]
        qr: bool,
    },
    /// Remove existing spoke from the hub.
    RemoveSpoke {
        /// Public key.
        public_key: String,
    },
    /// Synchronize the list of spokes with the relay.
    Sync,
    /// Set up Wireguard interface.
    Start,
    /// Tear down Wireguard interface.
    Stop,
    /// Reload Wireguard configuration.
    Reload,
    /// Get relay's public key. Low-level command.
    GetPublicKey {
        /// Relay's endpoint.
        #[arg(value_name = "IP[:PORT]")]
        endpoint: String,
    },
    /// Send peers' public keys to the relay. Low-level command.
    SetPeers {
        /// Relay's internal IP:PORT in Wireguard network.
        #[arg(value_name = "IP[:PORT]")]
        relay_socket_addr: SocketAddr,
        /// Peers' public keys.
        #[arg(value_name = "PUBLIC-KEY")]
        public_keys: Vec<String>,
    },
}

#[derive(Subcommand)]
enum SpokeCommand {
    /// Generate spoke configuration.
    Init {
        /// Relay's endpoint.
        #[arg(value_name = "IP[:PORT]")]
        relay: String,
    },
    /// Connect this spoke to the hub via the pre-configured relay.
    AddHub {
        /// Hub's public key in BASE64 format.
        public_key: String,
        /// Preshared key file.
        preshared_key_file: PathBuf,
    },
    /// Synchronize relay's public key.
    Sync,
    /// Set up Wireguard interface.
    Start,
    /// Tear down Wireguard interface.
    Stop,
    /// Reload Wireguard configuration.
    Reload,
}

fn main() -> ExitCode {
    match do_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}

fn do_main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    unsafe {
        libc::umask(0o077);
    }
    let args = Args::parse();
    if args.version {
        println!("{}", env!("VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    match args.command {
        Some(Command::Relay(command)) => match command {
            RelayCommand::Running => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                match client.call(UnixRequest::Running)? {
                    UnixResponse::Running => Ok(ExitCode::SUCCESS),
                    _ => Ok(ExitCode::FAILURE),
                }
            }
            RelayCommand::Status => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                let status = match client.call(UnixRequest::Status)? {
                    UnixResponse::Status(status) => status?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                print_status(&status);
                Ok(ExitCode::SUCCESS)
            }
            RelayCommand::Routes => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                let routes = match client.call(UnixRequest::Routes)? {
                    UnixResponse::Routes(routes) => routes?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                print_routes(&routes);
                Ok(ExitCode::SUCCESS)
            }
            RelayCommand::Sessions => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                let sessions = match client.call(UnixRequest::Sessions)? {
                    UnixResponse::Sessions(sessions) => sessions?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                print_sessions(&sessions);
                Ok(ExitCode::SUCCESS)
            }
            RelayCommand::PublicKey => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                let public_key = match client.call(UnixRequest::PublicKey)? {
                    UnixResponse::PublicKey(result) => result?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                println!("{}", public_key.to_base64());
                Ok(ExitCode::SUCCESS)
            }
            RelayCommand::Export => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                let config = match client.call(UnixRequest::Export)? {
                    UnixResponse::Export(result) => result?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                print!("{}", config);
                Ok(ExitCode::SUCCESS)
            }
        },
        Some(Command::Hub {
            config_file,
            command,
        }) => match command {
            HubCommand::GetPublicKey { endpoint } => {
                let endpoint: Endpoint = endpoint.parse()?;
                let mut client = WgxClient::new(endpoint)?;
                let public_key = client.retry(|client| client.get_public_key())?;
                println!("{}", public_key.to_base64());
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::SetPeers {
                relay_socket_addr,
                public_keys,
            } => {
                let public_keys: HashSet<PublicKey> = public_keys
                    .into_iter()
                    .map(|x| FromBase64::from_base64(&x))
                    .collect::<Result<HashSet<PublicKey>, _>>()
                    .map_err(|_| "invalid public key format")?;
                let mut client = WgxClient::new(relay_socket_addr)?;
                client.retry(|client| client.set_peers(&public_keys))?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Init { relay } => {
                init(relay, config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Sync => {
                let config_file = config_file.as_path();
                let mut config = Config::load(config_file)?;
                sync_relay_public_key(&mut config)?;
                sync_spoke_public_keys(&config)?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::AddSpoke { qr } => {
                let mut config = Config::load(config_file.as_path())?;
                let private_key = PrivateKey::random();
                let public_key: PublicKey = (&private_key).into();
                let preshared_key = PresharedKey::random();
                let mut wg_config: Vec<u8> = Vec::with_capacity(4096);
                let ip_address = config.random_ip_address()?;
                InterfaceConfig {
                    private_key,
                    address: IpNet::new(ip_address.addr(), config.interface.address.prefix_len())?,
                    fwmark: Default::default(),
                    listen_port: Default::default(),
                }
                .write_wireguard_config_ext(&mut wg_config)?;
                writeln!(&mut wg_config)?;
                let relay_endpoint = config.get_relay_endpoint()?;
                // hub
                PeerConfig {
                    public_key: (&config.interface.private_key).into(),
                    preshared_key: Some(preshared_key.clone()),
                    allowed_ips: Some(allowed_ip_any()),
                    endpoint: Some(relay_endpoint.clone()),
                    persistent_keepalive: Duration::ZERO,
                }
                .write_wireguard_config(&mut wg_config)?;
                writeln!(&mut wg_config)?;
                // relay
                config
                    .get_relay_peer_config()
                    .ok_or_else(|| format_error!("no relay is configured"))?
                    .write_wireguard_config(&mut wg_config)?;
                writeln!(&mut wg_config)?;
                config.peers.push(PeerConfig {
                    public_key,
                    preshared_key: Some(preshared_key),
                    allowed_ips: Some(ip_address),
                    endpoint: None,
                    persistent_keepalive: Duration::ZERO,
                });
                config.save()?;
                if qr {
                    let qrcode = QrCode::with_error_correction_level(&wg_config, EcLevel::H)?;
                    print!("{}", qrcode_to_string(qrcode));
                } else {
                    std::io::stdout().write_all(&wg_config)?;
                }
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::RemoveSpoke { public_key } => {
                let public_key = PublicKey::from_base64(&public_key)?;
                let config_file = config_file.as_path();
                let mut config = Config::load(config_file)?;
                let old_len = config.peers.len();
                config.peers.retain(|peer| peer.public_key != public_key);
                let new_len = config.peers.len();
                if old_len != new_len {
                    config.save()?;
                }
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Start => {
                wgx_start(config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Stop => {
                wgx_stop(config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Reload => {
                wgx_reload(config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
        },
        Some(Command::Spoke {
            config_file,
            command,
        }) => match command {
            SpokeCommand::Init { relay } => {
                init(relay, config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
            SpokeCommand::AddHub {
                public_key,
                preshared_key_file,
            } => {
                let public_key = PublicKey::from_base64(&public_key)?;
                let preshared_key =
                    PresharedKey::from_base64(&std::fs::read_to_string(preshared_key_file)?)?;
                let mut config = Config::load(config_file.as_path())?;
                let relay_endpoint = config.get_relay_endpoint()?;
                config.peers.push(PeerConfig {
                    public_key,
                    preshared_key: Some(preshared_key),
                    allowed_ips: Some(allowed_ip_any()),
                    endpoint: Some(relay_endpoint.clone()),
                    persistent_keepalive: Duration::ZERO,
                });
                Ok(ExitCode::SUCCESS)
            }
            SpokeCommand::Sync => {
                let config_file = config_file.as_path();
                let mut config = Config::load(config_file)?;
                sync_relay_public_key(&mut config)?;
                Ok(ExitCode::SUCCESS)
            }
            SpokeCommand::Start => {
                wgx_start(config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
            SpokeCommand::Stop => {
                wgx_stop(config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
            SpokeCommand::Reload => {
                wgx_reload(config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
        },
        None => {
            eprintln!("{}", Args::command().render_help());
            Ok(ExitCode::FAILURE)
        }
    }
}

fn init(relay: String, config_file: &Path) -> Result<(), Error> {
    let relay: Endpoint = relay.parse().map_err(Error::map)?;
    let mut client = WgxClient::new(&relay)?;
    let relay_public_key = client.retry(|client| client.get_public_key())?;
    eprintln!("✓ Relay public key: {}", relay_public_key.to_base64());
    let mut config = Config::load(config_file)?;
    config.set_relay(Some(relay.clone()), relay_public_key)?;
    config.save()?;
    Ok(())
}

fn sync_relay_public_key(config: &mut Config) -> Result<(), Error> {
    let endpoint = config.get_relay_endpoint()?;
    let mut client = WgxClient::new(endpoint)?;
    let relay_public_key = client.retry(|client| client.get_public_key())?;
    eprintln!("✓ Relay public key: {}", relay_public_key.to_base64());
    if Some(&relay_public_key) != config.get_relay_public_key() {
        config.set_relay(Some(endpoint.clone()), relay_public_key)?;
        config.save()?;
        eprintln!("✓ Updated relay public key");
        wg_reload(config)?;
    }
    Ok(())
}

fn sync_spoke_public_keys(config: &Config) -> Result<(), Error> {
    let (relay_ip_addr, peers_public_keys) = config.get_relay_ip_addr_and_peers_public_keys()?;
    eprintln!("✓ Relay inner IP address: {}", relay_ip_addr);
    if peers_public_keys.is_empty() {
        return Ok(());
    }
    let endpoint = Endpoint::IpAddr(relay_ip_addr);
    let mut client = WgxClient::new(endpoint)?;
    client.retry(|client| client.set_peers(&peers_public_keys))?;
    eprintln!(
        "✓ Published peers: {}",
        peers_public_keys
            .iter()
            .fold(String::with_capacity(4096), |mut a, b| {
                if !a.is_empty() {
                    a.push_str(", ");
                }
                a.push_str(&b.to_base64());
                a
            })
    );
    Ok(())
}

fn wgx_start(config_file: &Path) -> Result<(), Error> {
    let config = Config::load(config_file)?;
    let wg = Wg::new(config.interface_name.0);
    wg.stop()?;
    wg.start(&config.interface, &config.peers)?;
    Ok(())
}

fn wgx_stop(config_file: &Path) -> Result<(), Error> {
    let config = Config::load(config_file)?;
    let wg = Wg::new(config.interface_name.0);
    wg.stop()?;
    Ok(())
}

fn wgx_reload(config_file: &Path) -> Result<(), Error> {
    let config = Config::load(config_file)?;
    wg_reload(&config)?;
    Ok(())
}

fn wg_reload(config: &Config) -> Result<(), Error> {
    let wg = Wg::new(config.interface_name.0.clone());
    wg.reload(&config.interface, &config.peers)?;
    eprintln!("✓ Synced wg config");
    Ok(())
}

fn print_status(status: &Status) {
    let now = SystemTime::now();
    println!(
        "{} {}",
        "relay:".green().bold(),
        status.public_key.to_base64().green()
    );
    println!("  {} {}", "listening port:".bold(), status.listen_port);
    println!(
        "  {} {}",
        "allowed public keys:".bold(),
        status.allowed_public_keys
    );
    println!();
    for (public_key, peer) in status.auth_peers.iter() {
        println!(
            "{} {}",
            "peer:".yellow().bold(),
            public_key.to_base64().yellow()
        );
        println!("  {} {}", "endpoint:".bold(), peer.socket_addr);
        println!(
            "  {} {}",
            "latest handshake:".bold(),
            format_latest_handshake(peer.latest_handshake, "now", now)
        );
        println!(
            "  {} {}",
            "transfer:".bold(),
            format_transfer(peer.bytes_received, peer.bytes_sent)
        );
        println!();
    }
}

fn print_routes(routes: &Routes) {
    for (hub, spokes) in routes.hub_to_spokes.iter() {
        for spoke in spokes.iter() {
            println!("edge {} {}", hub.to_base64(), spoke.to_base64());
        }
    }
}

fn print_sessions(sessions: &Sessions) {
    let now = SystemTime::now();
    for ((spoke_public_key, hub_public_key), session) in sessions.sessions.iter() {
        println!("{}", "session:".green().bold());
        println!(
            "  {} {}",
            "spoke public key:".bold(),
            spoke_public_key.to_base64()
        );
        println!(
            "  {} {}",
            "hub public key:".bold(),
            hub_public_key.to_base64()
        );
        println!(
            "  {} {}",
            "latest handshake:".bold(),
            match session.latest_handshake {
                Some(t) => format_latest_handshake(t, "now", now),
                None => "never".into(),
            }
        );
        println!(
            "  {} {}",
            "transfer:".bold(),
            format_transfer(session.bytes_received, session.bytes_sent)
        );
        println!();
    }
}

fn format_latest_handshake(latest_handshake: SystemTime, default: &str, now: SystemTime) -> String {
    match now.duration_since(latest_handshake) {
        Ok(d) => format!("{} ago", ColoredDuration(format_duration(d))),
        Err(_) => default.to_string(),
    }
}

fn format_transfer(received: u64, sent: u64) -> String {
    format!(
        "{} received, {} sent",
        ColoredBytes(format_bytes(received)),
        ColoredBytes(format_bytes(sent))
    )
}

struct ColoredBytes(FormatBytes);

impl Display for ColoredBytes {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0.integer)?;
        if self.0.fraction != 0 {
            write!(f, ".{}", self.0.fraction)?;
        }
        write!(f, " {}", self.0.unit.cyan())
    }
}

struct ColoredDuration(FormatDuration);

impl Display for ColoredDuration {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0.integer)?;
        if self.0.fraction != 0 {
            write!(f, ".{}", self.0.fraction)?;
        }
        write!(f, " {}", self.0.unit.cyan())
    }
}
