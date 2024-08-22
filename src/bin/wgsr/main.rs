use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::Subcommand;
use wgproto::PublicKey;
use wgsr::ExportFormat;
use wgsr::FromBase64;
use wgsr::Request;
use wgsr::Response;
use wgsr::Status;
use wgsr::ToBase64;
use wgsr::DEFAULT_UNIX_SOCKET_PATH;

use self::error::*;
use self::unix::*;

mod error;
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
    /// Check if wgsr daemon is running.
    Running,
    /// Get relay status.
    Status,
    /// Export peer configuration.
    Export {
        /// Output format.
        #[arg(
            short = 'f',
            long = "format",
            value_name = "config|public-key",
            default_value = "config",
            value_parser = export_format_parser,
        )]
        format: ExportFormat,
    },
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
            match client.call(Request::Running)? {
                Response::Running => Ok(ExitCode::SUCCESS),
                _ => Ok(ExitCode::FAILURE),
            }
        }
        Some(Command::Status) | None => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let status = match client.call(Request::Status)? {
                Response::Status(status) => status?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print_status(&status);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Export { format }) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let config = match client.call(Request::Export { format })? {
                Response::Export(result) => result?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print!("{}", config);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_status(status: &Status) {
    for (public_key, peer) in status.auth_peers.iter() {
        eprintln!(
            "auth-peer {} {} {}->{}",
            public_key.to_base64(),
            peer.socket_addr,
            peer.sender_index,
            peer.receiver_index
        );
    }
    for (hub, spokes) in status.hub_to_spokes.iter() {
        for spoke in spokes.iter() {
            eprintln!("edge {} {}", hub.to_base64(), spoke.to_base64());
        }
    }
    for ((sender_socket_addr, receiver_index), receiver_public_key) in
        status.destination_to_public_key.iter()
    {
        eprintln!(
            "route {} {} -> {}",
            sender_socket_addr,
            receiver_index,
            receiver_public_key.to_base64()
        );
    }
    println!("-");
}

fn base64_parser<T>(s: &str) -> Result<T, Box<dyn std::error::Error + Sync + Send + 'static>>
where
    T: FromBase64,
{
    Ok(T::from_base64(s).map_err(|_| "base64 i/o error")?)
}

fn export_format_parser(
    s: &str,
) -> Result<ExportFormat, Box<dyn std::error::Error + Sync + Send + 'static>> {
    match s {
        "config" => Ok(ExportFormat::Config),
        "public-key" => Ok(ExportFormat::PublicKey),
        other => Err(format!("unknown export format: `{}`", other).into()),
    }
}
