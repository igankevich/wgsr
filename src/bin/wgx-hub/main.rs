use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::net::UdpSocket;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::Parser;
use clap::Subcommand;
use rand_core::OsRng;
use rand_core::RngCore;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::MessageKindExt;
use wgx::RpcDecode;
use wgx::RpcEncode;
use wgx::RpcRequest;
use wgx::RpcRequestBody;
use wgx::RpcResponse;
use wgx::RpcResponseBody;
use wgx::ToBase64;
use wgx::DEFAULT_LISTEN_PORT;

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
            for i in 1..=UDP_NUM_RETRIES {
                let public_key = match get_public_key(endpoint) {
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        eprintln!("retrying... attempt {}/{}", i, UDP_NUM_RETRIES);
                        continue;
                    }
                    other => other,
                }?;
                println!("{}", public_key.to_base64());
                return Ok(ExitCode::SUCCESS);
            }
            eprintln!("max. no. of retries reached");
            Ok(ExitCode::FAILURE)
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
            let request = RpcRequest {
                id: OsRng.next_u32(),
                body: RpcRequestBody::SetPeers(public_keys),
            };
            let mut buffer = Vec::with_capacity(4096);
            request.encode(&mut buffer);
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0_u16))?;
            socket.set_read_timeout(Some(UDP_READ_TIMEOUT))?;
            socket.set_write_timeout(Some(UDP_WRITE_TIMEOUT))?;
            socket.connect(relay_socket_addr)?;
            socket.send(&buffer)?;
            socket.recv(&mut buffer)?;
            let response = RpcResponse::decode(&buffer).map_err(|_| "invalid response received")?;
            if response.request_id != request.id {
                return Err("invalid response received".into());
            }
            match response.body {
                RpcResponseBody::SetPeers(result) => {
                    result.map_err(|_| "invalid response received")?
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::SUCCESS),
    }
}

fn get_public_key(socket_addr: SocketAddr) -> Result<PublicKey, std::io::Error> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0_u16))?;
    socket.set_read_timeout(Some(UDP_READ_TIMEOUT))?;
    socket.set_write_timeout(Some(UDP_WRITE_TIMEOUT))?;
    socket.connect(socket_addr)?;
    socket.send(&[MessageKindExt::GetPublicKey as u8])?;
    let mut data = [0_u8; 32];
    let nreceived = socket.recv(&mut data[..])?;
    if nreceived != data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid public key received",
        ));
    }
    Ok(data.into())
}

enum Endpoint {
    SocketAddr(SocketAddr),
    IpAddr(IpAddr),
    DnsNameWithPort(DnsNameWithPort),
    DnsName(String),
}

impl Endpoint {
    fn to_socket_addr(
        &self,
        default_port: u16,
    ) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
        match self {
            Self::SocketAddr(x) => Ok(x.to_socket_addrs()?.next()),
            Self::IpAddr(x) => Ok(Some(SocketAddr::new(*x, default_port))),
            Self::DnsNameWithPort(x) => Ok(x.name.to_socket_addrs()?.next()),
            Self::DnsName(x) => Ok(format!("{}:{}", x, default_port).to_socket_addrs()?.next()),
        }
    }
}

impl FromStr for Endpoint {
    type Err = Box<dyn std::error::Error>;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = other.parse::<SocketAddr>() {
            return Ok(Self::SocketAddr(socket_addr));
        }
        if let Ok(ipaddr) = other.parse::<IpAddr>() {
            return Ok(Self::IpAddr(ipaddr));
        }
        if let Ok(dns_name_with_port) = other.parse::<DnsNameWithPort>() {
            return Ok(Self::DnsNameWithPort(dns_name_with_port));
        }
        Ok(Self::DnsName(other.into()))
    }
}

struct DnsNameWithPort {
    name: String,
}

impl FromStr for DnsNameWithPort {
    type Err = Box<dyn std::error::Error>;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        match other.rfind(':') {
            Some(_) => Ok(Self { name: other.into() }),
            None => Err(format!("no port in `{}`", other).into()),
        }
    }
}

const UDP_READ_TIMEOUT: Duration = Duration::from_secs(7);
const UDP_WRITE_TIMEOUT: Duration = UDP_READ_TIMEOUT;
const UDP_NUM_RETRIES: usize = 3;
