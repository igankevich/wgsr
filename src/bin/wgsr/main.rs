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
    arg_required_else_help = true,
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
    /// Relay commands.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Hub commands.
    Hub {
        #[command(subcommand)]
        command: HubCommand,
    },
    /// Spoke commands.
    Spoke {
        #[command(subcommand)]
        command: SpokeCommand,
    },
    /// Export peer configuration.
    Export {
        /// Listen port.
        listen_port: NonZeroU16,
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
                Response::Running(status) => status?,
                _ => return Ok(ExitCode::FAILURE),
            };
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Status) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let status = match client.call(Request::Status)? {
                Response::Status(status) => status?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print_status(&status);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Relay { command }) => match command {
            RelayCommand::Add { listen_port } => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                let allocated_listen_port = match client.call(Request::RelayAdd {
                    listen_port,
                    persistent: true,
                })? {
                    Response::RelayAdd(listen_port) => listen_port?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                if listen_port.is_none() {
                    println!("{}", allocated_listen_port);
                }
                Ok(ExitCode::SUCCESS)
            }
            RelayCommand::Rm { listen_port } => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                match client.call(Request::RelayRemove {
                    listen_port,
                    persistent: true,
                })? {
                    Response::RelayRemove(result) => result?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                Ok(ExitCode::SUCCESS)
            }
        },
        Some(Command::Hub { command }) => match command {
            HubCommand::Add {
                listen_port,
                public_key,
            } => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                match client.call(Request::HubAdd {
                    listen_port,
                    public_key,
                    persistent: true,
                })? {
                    Response::HubAdd(result) => result?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                Ok(ExitCode::SUCCESS)
            }
            HubCommand::Rm {
                listen_port,
                public_key,
            } => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                match client.call(Request::HubRemove {
                    listen_port,
                    public_key,
                    persistent: true,
                })? {
                    Response::HubRemove(result) => result?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                Ok(ExitCode::SUCCESS)
            }
        },
        Some(Command::Spoke { command }) => match command {
            SpokeCommand::Add {
                listen_port,
                public_key,
            } => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                match client.call(Request::SpokeAdd {
                    listen_port,
                    public_key,
                    persistent: true,
                })? {
                    Response::SpokeAdd(result) => result?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                Ok(ExitCode::SUCCESS)
            }
            SpokeCommand::Rm {
                listen_port,
                public_key,
            } => {
                let mut client = UnixClient::new(args.unix_socket_path)?;
                match client.call(Request::SpokeRemove {
                    listen_port,
                    public_key,
                    persistent: true,
                })? {
                    Response::SpokeRemove(result) => result?,
                    _ => return Ok(ExitCode::FAILURE),
                };
                Ok(ExitCode::SUCCESS)
            }
        },
        Some(Command::Export {
            listen_port,
            format,
        }) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let config = match client.call(Request::Export {
                listen_port,
                format,
            })? {
                Response::Export(result) => result?,
                _ => return Ok(ExitCode::FAILURE),
            };
            print!("{}", config);
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::FAILURE),
    }
}

fn print_status(status: &Status) {
    if status.servers.is_empty() {
        return;
    }
    println!(
        "{:<23}{:<23}{:<23}{:<23}{:<23}{:<46}",
        "Local", "Type", "Status", "Remote", "Session", "PublicKey"
    );
    for server in status.servers.iter() {
        if let Some(hub) = server.hub.as_ref() {
            println!(
                "{:<23}{:<23}{:<23}{:<23}{:<23}{}",
                server.socket_addr,
                "hub-auth",
                "authorized",
                hub.socket_addr,
                hub.session_index,
                hub.public_key.to_base64(),
            );
        }
        for spoke in server.spokes.iter() {
            println!(
                "{:<23}{:<23}{:<23}{:<23}{:<23}{}",
                server.socket_addr,
                "spoke-auth",
                "authorized",
                spoke.socket_addr,
                spoke.session_index,
                spoke.public_key.to_base64(),
            );
        }
        for other_peer in server.peers.iter() {
            println!(
                "{:<23}{:<23}{:<23}{:<23}{:<23}",
                server.socket_addr,
                other_peer.kind.as_str(),
                other_peer.status.as_str(),
                other_peer.socket_addr,
                other_peer.session_index,
            );
        }
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
        "preshared-key" => Ok(ExportFormat::PresharedKey),
        other => Err(format!("unknown export format: `{}`", other).into()),
    }
}
