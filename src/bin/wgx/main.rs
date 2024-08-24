use std::fmt::Display;
use std::fmt::Formatter;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use clap::Parser;
use clap::Subcommand;
use colored::Colorize;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::Routes;
use wgx::Sessions;
use wgx::Status;
use wgx::ToBase64;
use wgx::UnixRequest;
use wgx::UnixResponse;
use wgx::DEFAULT_UNIX_SOCKET_PATH;

use self::error::*;
use self::units::*;
use self::unix::*;
use crate::format_bytes;
use crate::format_duration;

mod error;
mod units;
mod unix;

#[derive(Parser)]
#[command(
    about = "Wireguard Secure Relay.",
    long_about = None,
    trailing_var_arg = true
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
    /// Command to run.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
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
    /// Export peer configuration.
    Export,
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Add new relay.
    Add {
        /// Listen port.
        listen_port: Option<NonZeroU16>,
    },
    /// Remove existing relay.
    Rm {
        /// Listen port.
        listen_port: NonZeroU16,
    },
}

#[derive(Subcommand)]
enum HubCommand {
    /// Add new hub.
    Add {
        /// Relay listen port.
        listen_port: NonZeroU16,
        /// Public key.
        #[arg(value_name = "BASE64", value_parser = base64_parser::<PublicKey>)]
        public_key: PublicKey,
    },
    /// Remove existing hub.
    Rm {
        /// Relay listen port.
        listen_port: NonZeroU16,
        /// Public key.
        #[arg(value_name = "BASE64", value_parser = base64_parser::<PublicKey>)]
        public_key: PublicKey,
    },
}

#[derive(Subcommand)]
enum SpokeCommand {
    /// Add new hub.
    Add {
        /// Relay listen port.
        listen_port: NonZeroU16,
        /// Public key.
        #[arg(value_name = "BASE64", value_parser = base64_parser::<PublicKey>)]
        public_key: PublicKey,
    },
    /// Remove existing hub.
    Rm {
        /// Relay listen port.
        listen_port: NonZeroU16,
        /// Public key.
        #[arg(value_name = "BASE64", value_parser = base64_parser::<PublicKey>)]
        public_key: PublicKey,
    },
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
        Some(Command::Running) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            match client.call(UnixRequest::Running)? {
                UnixResponse::Running => Ok(ExitCode::SUCCESS),
                _ => Ok(ExitCode::FAILURE),
            }
        }
        Some(Command::Status) | None => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let status = match client.call(UnixRequest::Status)? {
                UnixResponse::Status(status) => status?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print_status(&status);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Routes) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let routes = match client.call(UnixRequest::Routes)? {
                UnixResponse::Routes(routes) => routes?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print_routes(&routes);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Sessions) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let sessions = match client.call(UnixRequest::Sessions)? {
                UnixResponse::Sessions(sessions) => sessions?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print_sessions(&sessions);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::PublicKey) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let public_key = match client.call(UnixRequest::PublicKey)? {
                UnixResponse::PublicKey(result) => result?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print!("{}", public_key.to_base64());
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Export) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let config = match client.call(UnixRequest::Export)? {
                UnixResponse::Export(result) => result?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print!("{}", config);
            Ok(ExitCode::SUCCESS)
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
    for ((sender_socket_addr, receiver_index), receiver_public_key) in sessions.sessions.iter() {
        println!(
            "{} -> {} {}",
            sender_socket_addr,
            receiver_index,
            receiver_public_key.to_base64()
        );
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

fn base64_parser<T>(s: &str) -> Result<T, Box<dyn std::error::Error + Sync + Send + 'static>>
where
    T: FromBase64,
{
    Ok(T::from_base64(s).map_err(|e| e.to_string())?)
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
