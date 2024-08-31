use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::ExitCode;

use clap::Parser;
use clap::Subcommand;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::ToBase64;
use wgx::DEFAULT_LISTEN_PORT;

use self::endpoint::*;
use self::wg::*;
use self::wgx_client::*;
use crate::get_relay_ip_addr_and_peers_public_keys;

mod endpoint;
mod wg;
mod wgx_client;

#[derive(Parser)]
#[command(
    about = "Wireguard Secure Relay.",
    long_about = None,
    trailing_var_arg = true,
    arg_required_else_help = true
)]
struct Args {
    /// Print version.
    #[clap(long, action)]
    version: bool,
    /// Command to run.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Get relay's public key.
    GetPublicKey {
        /// Relay's endpoint.
        #[arg(value_name = "IP:PORT")]
        endpoint: String,
    },
    /// Send peers' public keys to the relay.
    SetPeers {
        /// Relay's internal IP:PORT in Wireguard network.
        #[arg(value_name = "IP:PORT")]
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
        #[arg(value_name = "IP:PORT")]
        endpoint: String,
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
    let args = Args::parse();
    if args.version {
        println!("{}", env!("VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    match args.command {
        Some(Command::GetPublicKey {
            endpoint: endpoint_str,
        }) => {
            let endpoint: Endpoint = endpoint_str.parse()?;
            let endpoint = endpoint
                .to_socket_addr(DEFAULT_LISTEN_PORT)?
                .ok_or_else(|| format!("failed to resolve `{}`", endpoint_str))?;
            let mut client = WgxClient::new(endpoint)?;
            let public_key = client.retry(|client| client.get_public_key())?;
            println!("{}", public_key.to_base64());
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::SetPeers {
            relay_socket_addr,
            public_keys,
        }) => {
            let public_keys: HashSet<PublicKey> = public_keys
                .into_iter()
                .map(|x| FromBase64::from_base64(&x))
                .collect::<Result<HashSet<PublicKey>, _>>()
                .map_err(|_| "invalid public key format")?;
            let mut client = WgxClient::new(relay_socket_addr)?;
            client.retry(|client| client.set_peers(&public_keys))?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Join {
            interface,
            endpoint: endpoint_str,
        }) => {
            let endpoint: Endpoint = endpoint_str.parse()?;
            let endpoint = endpoint
                .to_socket_addr(DEFAULT_LISTEN_PORT)?
                .ok_or_else(|| format!("failed to resolve `{}`", endpoint_str))?;
            let mut client = WgxClient::new(endpoint)?;
            let relay_public_key = client.retry(|client| client.get_public_key())?;
            eprintln!("✓ Relay public key: {}", relay_public_key.to_base64());
            let (relay_ip_addr, peers_public_keys) =
                get_relay_ip_addr_and_peers_public_keys(&interface, &relay_public_key, endpoint)?;
            eprintln!("✓ Relay inner IP address: {}", relay_ip_addr);
            eprintln!(
                "✓ Peers: {}",
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
            let endpoint = Endpoint::IpAddr(relay_ip_addr);
            let endpoint = endpoint
                .to_socket_addr(DEFAULT_LISTEN_PORT)?
                .ok_or_else(|| format!("failed to resolve `{}`", endpoint_str))?;
            let mut client = WgxClient::new(endpoint)?;
            client.retry(|client| client.set_peers(&peers_public_keys))?;
            eprintln!("✓ Published peers");
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::SUCCESS),
    }
}
