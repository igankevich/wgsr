use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::Subcommand;
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
    Status,
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
    let args = Args::parse();
    if args.version {
        println!("{}", env!("VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    match args.command {
        Some(Command::Status) => {
            let mut client = UnixClient::new(args.unix_socket_path)?;
            let status = match client.call(Request::Status)? {
                Response::Status(status) => status?,
                //_ => return Ok(ExitCode::FAILURE),
            };
            print_status(&status);
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::FAILURE),
    }
}

fn print_status(status: &Status) {
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
                other_peer.peer_type.as_str(),
                other_peer.status.as_str(),
                other_peer.socket_addr,
                other_peer.session_index,
            );
        }
    }
    println!("-");
}
