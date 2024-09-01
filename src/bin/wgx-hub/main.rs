use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::ExitCode;

use clap::Parser;
use clap::Subcommand;
use qrencode::EcLevel;
use qrencode::QrCode;
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::ToBase64;
use wgx::DEFAULT_LISTEN_PORT;

use self::endpoint::*;
use self::qrcode::*;
use self::wg::*;
use self::wgx_client::*;
use crate::get_relay_ip_addr_and_peers_public_keys;

mod endpoint;
mod qrcode;
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
        Some(Command::Export {
            qr,
            interface,
            endpoint: endpoint_str,
        }) => {
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
            writeln!(&mut config, "PersistentKeepalive = 23")?;
            writeln!(&mut config, "AllowedIPs = TODO")?;
            writeln!(&mut config)?;
            // relay
            writeln!(&mut config, "[Peer]")?;
            writeln!(&mut config, "PublicKey = {}", relay_public_key.to_base64())?;
            writeln!(&mut config, "Endpoint = {}", wg_endpoint)?;
            writeln!(&mut config, "PersistentKeepalive = 23")?;
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
        None => Ok(ExitCode::SUCCESS),
    }
}
