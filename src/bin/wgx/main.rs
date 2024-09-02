use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use clap::CommandFactory;
use clap::Parser;
use clap::Subcommand;
use colored::Colorize;
use qrencode::EcLevel;
use qrencode::QrCode;
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::Routes;
use wgx::Sessions;
use wgx::Status;
use wgx::ToBase64;
use wgx::UnixRequest;
use wgx::UnixResponse;
use wgx::DEFAULT_LISTEN_PORT;
use wgx::DEFAULT_PERSISTENT_KEEPALIVE;
use wgx::DEFAULT_UNIX_SOCKET_PATH;

use self::command_hr::*;
use self::endpoint::*;
use self::error::*;
use self::hub_config::*;
use self::qrcode::*;
use self::units::*;
use self::unix::*;
use self::wg::*;
use self::wgx_client::*;

mod command_hr;
mod endpoint;
mod error;
mod hub_config;
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
    /// Configuration file path.
    #[arg(
        short = 'c',
        long = "config",
        value_name = "path",
        default_value = DEFAULT_CONFIGURATION_FILE_PATH
    )]
    config_file: PathBuf,
    /// RelayCommand to run.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Relay commands.
    #[command(subcommand)]
    Relay(RelayCommand),
    /// Hub commands.
    #[command(subcommand)]
    Hub(HubCommand),
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

fn main() -> ExitCode {
    match do_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}

#[derive(Subcommand)]
enum HubCommand {
    /// Get relay's public key.
    GetPublicKey {
        /// Relay's endpoint.
        #[arg(value_name = "IP[:PORT]")]
        endpoint: String,
    },
    /// Send peers' public keys to the relay.
    SetPeers {
        /// Relay's internal IP:PORT in Wireguard network.
        #[arg(value_name = "IP[:PORT]")]
        relay_socket_addr: SocketAddr,
        /// Peers' public keys.
        #[arg(value_name = "PUBLIC-KEY")]
        public_keys: Vec<String>,
    },
    /// Query relay's public key and set peers automatically.
    Join {
        /// Wireguard network interface name.
        #[arg(value_name = "NAME")]
        interface: String,
        /// Relay's endpoint.
        #[arg(value_name = "IP[:PORT]")]
        endpoint: String,
    },
    /// Generate spoke configuration.
    Export {
        /// Export as QR-code.
        #[clap(long, action)]
        qr: bool,
        /// Wireguard network interface name.
        #[arg(value_name = "NAME")]
        interface: String,
        /// Relay's endpoint.
        #[arg(value_name = "IP[:PORT]")]
        endpoint: String,
    },
    Init,
    Start,
    Stop,
    Reload,
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
        Some(Command::Hub(command)) => match command {
            HubCommand::GetPublicKey {
                endpoint: endpoint_str,
            } => {
                let endpoint: Endpoint = endpoint_str.parse()?;
                let endpoint = endpoint
                    .to_socket_addr(DEFAULT_LISTEN_PORT)?
                    .ok_or_else(|| format!("failed to resolve `{}`", endpoint_str))?;
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
            HubCommand::Join {
                interface,
                endpoint: endpoint_str,
            } => {
                let endpoint: Endpoint = endpoint_str.parse()?;
                let endpoint = endpoint
                    .to_socket_addr(DEFAULT_LISTEN_PORT)?
                    .ok_or_else(|| format!("failed to resolve `{}`", endpoint_str))?;
                let mut client = WgxClient::new(endpoint)?;
                let relay_public_key = client.retry(|client| client.get_public_key())?;
                eprintln!("✓ Relay public key: {}", relay_public_key.to_base64());
                let (relay_ip_addr, peers_public_keys) = get_relay_ip_addr_and_peers_public_keys(
                    &interface,
                    &relay_public_key,
                    endpoint,
                )?;
                eprintln!("✓ Relay inner IP address: {}", relay_ip_addr);
                if peers_public_keys.is_empty() {
                    return Ok(ExitCode::SUCCESS);
                }
                let endpoint = Endpoint::IpAddr(relay_ip_addr);
                let endpoint = endpoint
                    .to_socket_addr(DEFAULT_LISTEN_PORT)?
                    .ok_or_else(|| format!("failed to resolve `{}`", endpoint_str))?;
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
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Export {
                qr,
                interface,
                endpoint: endpoint_str,
            } => {
                let _config = Config::default();
                let endpoint: Endpoint = endpoint_str.parse()?;
                let socket_addr = endpoint
                    .to_socket_addr(DEFAULT_LISTEN_PORT)?
                    .ok_or_else(|| format!("failed to resolve `{}`", endpoint_str))?;
                let mut client = WgxClient::new(socket_addr)?;
                let relay_public_key = client.retry(|client| client.get_public_key())?;
                let mut config = String::with_capacity(4096);
                let wg_endpoint = endpoint.to_string(DEFAULT_LISTEN_PORT);
                use std::fmt::Write;
                // interface
                writeln!(&mut config, "[Interface]")?;
                writeln!(
                    &mut config,
                    "PrivateKey = {}",
                    PrivateKey::random().to_base64()
                )?;
                writeln!(&mut config, "Address = TODO")?;
                writeln!(&mut config)?;
                // hub
                writeln!(&mut config, "[Peer]")?;
                writeln!(
                    &mut config,
                    "PublicKey = {}",
                    get_wg_public_key(&interface)?.to_base64()
                )?;
                writeln!(&mut config, "Endpoint = {}", wg_endpoint)?;
                writeln!(
                    &mut config,
                    "PersistentKeepalive = {}",
                    DEFAULT_PERSISTENT_KEEPALIVE.as_secs()
                )?;
                writeln!(&mut config, "AllowedIPs = TODO")?;
                writeln!(&mut config)?;
                // relay
                writeln!(&mut config, "[Peer]")?;
                writeln!(&mut config, "PublicKey = {}", relay_public_key.to_base64())?;
                writeln!(&mut config, "Endpoint = {}", wg_endpoint)?;
                writeln!(
                    &mut config,
                    "PersistentKeepalive = {}",
                    DEFAULT_PERSISTENT_KEEPALIVE.as_secs()
                )?;
                writeln!(&mut config, "AllowedIPs =")?;
                let config = if qr {
                    // remove comments and empty lines
                    let mut short_config = String::with_capacity(config.len());
                    for line in config.lines() {
                        let line = match line.find('#') {
                            Some(i) => &line[..i],
                            None => line,
                        }
                        .trim();
                        if !line.is_empty() {
                            short_config.push_str(line);
                            short_config.push('\n');
                        }
                    }
                    let qrcode =
                        QrCode::with_error_correction_level(short_config.as_bytes(), EcLevel::H)?;
                    qrcode_to_string(qrcode)
                } else {
                    config
                };
                print!("{}", config);
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Init => {
                let config = Config::load(args.config_file.as_path())?;
                config.save(args.config_file.as_path())?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Start => {
                let config_file = args.config_file.as_path();
                let config = Config::load(config_file)?;
                if !config_file.exists() {
                    config.save(config_file)?;
                }
                let wg = Wg::new(config.interface_name);
                wg.stop()?;
                wg.start(&config.interface)?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Stop => {
                let config = Config::load(args.config_file.as_path())?;
                let wg = Wg::new(config.interface_name);
                wg.stop()?;
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Reload => {
                let config = Config::load(args.config_file.as_path())?;
                let wg = Wg::new(config.interface_name);
                wg.reload(&config.interface)?;
                Ok(ExitCode::SUCCESS)
            }
        },
        None => {
            eprintln!("{}", Args::command().render_help());
            Ok(ExitCode::FAILURE)
        }
    }
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
