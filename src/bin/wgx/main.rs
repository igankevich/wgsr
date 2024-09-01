use std::fmt::Display;
use std::fmt::Formatter;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use clap::Parser;
use clap::Subcommand;
use colored::Colorize;
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
    about = "Wireguard Relay Extensions.",
    long_about = None,
    trailing_var_arg = true,
    arg_required_else_help=true
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
    /// RelayCommand to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Relay commands.
    #[command(subcommand)]
    Relay(RelayCommand),
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
        Command::Relay(command) => match command {
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
