use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Duration;

use rand::Rng;
use rand_core::OsRng;
use rand_core::RngCore;
use wgproto::PublicKey;
use wgx::MessageKindExt;
use wgx::RpcDecode;
use wgx::RpcEncode;
use wgx::RpcRequest;
use wgx::RpcRequestBody;
use wgx::RpcResponse;
use wgx::RpcResponseBody;

pub(crate) struct WgxClient {
    socket: UdpSocket,
}

impl WgxClient {
    pub(crate) fn new(socket_addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0_u16))?;
        socket.connect(socket_addr)?;
        Ok(Self { socket })
    }

    pub(crate) fn get_public_key(&mut self) -> Result<PublicKey, std::io::Error> {
        self.socket.send(&[MessageKindExt::GetPublicKey as u8])?;
        let mut data = [0_u8; 32];
        let nreceived = self.socket.recv(&mut data[..])?;
        if nreceived != data.len() {
            return Err(other_error("invalid public key received"));
        }
        Ok(data.into())
    }

    pub(crate) fn set_peers(
        &mut self,
        public_keys: &HashSet<PublicKey>,
    ) -> Result<(), std::io::Error> {
        let request = RpcRequest {
            id: OsRng.next_u32(),
            body: RpcRequestBody::SetPeers(public_keys.clone()),
        };
        let mut buffer = Vec::with_capacity(4096);
        request.encode(&mut buffer);
        self.socket.send(&buffer)?;
        self.socket.recv(&mut buffer)?;
        let response =
            RpcResponse::decode(&buffer).map_err(|_| other_error("invalid response received"))?;
        if response.request_id != request.id {
            return Err(other_error("invalid response received"));
        }
        match response.body {
            RpcResponseBody::SetPeers(result) => {
                result.map_err(|_| other_error("invalid response received"))?
            }
        }
        Ok(())
    }

    pub(crate) fn retry<R, F>(&mut self, mut callback: F) -> Result<R, std::io::Error>
    where
        F: FnMut(&mut Self) -> Result<R, std::io::Error>,
    {
        let mut timeout = MIN_TIMEOUT;
        for i in 1..=UDP_NUM_RETRIES {
            let jitter = (timeout.as_millis() as u64) * 3 / 4;
            let jitter = Duration::from_millis(OsRng.gen_range(0..jitter));
            let dt = Some(timeout + jitter);
            self.socket.set_write_timeout(dt)?;
            self.socket.set_read_timeout(dt)?;
            match callback(self) {
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if i >= 2 {
                        eprintln!("retrying... attempt {}/{}", i, UDP_NUM_RETRIES);
                    }
                    timeout *= 2;
                    continue;
                }
                other => return other,
            };
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "max. no. of retries reached",
        ))
    }
}

fn other_error(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, message)
}

const MIN_TIMEOUT: Duration = Duration::from_secs(1);
const UDP_NUM_RETRIES: usize = 4;
