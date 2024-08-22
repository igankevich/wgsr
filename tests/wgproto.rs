use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Duration;
use std::time::Instant;

use wgproto::Node;
use wgproto::Peer;
use wgproto::PresharedKey;
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::RpcEncode;
use wgx::RpcRequest;
use wgx::RpcRequestBody;

use crate::wgxd::Wgxd;

mod wgxd;

#[test]
fn echo_server_one_hub_one_spoke() {
    let hub_private_key = PrivateKey::random();
    let hub_public_key: PublicKey = (&hub_private_key).into();
    let spoke_private_key = PrivateKey::random();
    let spoke_public_key: PublicKey = (&spoke_private_key).into();
    // run wgxd
    let wgxd = Wgxd::new();
    wgxd.wait_until_started();
    let output = wgxd.wgx(["public-key"]).output().unwrap();
    let wgxd_public_key = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
    let wgxd_public_key = PublicKey::from_base64(wgxd_public_key.trim()).unwrap();
    let wgxd_preshared_key: PresharedKey = [0_u8; 32].into();
    assert_output!(output);
    let wgxd_port: u16 = wgxd.listen_port();
    let wgxd_socket_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), wgxd_port);
    // setup wireguard nodes
    let preshared_key = PresharedKey::random();
    let mut hub: Node<SocketAddr> = Node::new(
        hub_private_key,
        vec![
            // real peer
            Peer {
                public_key: spoke_public_key,
                preshared_key: preshared_key.clone(),
                persistent_keepalive: Duration::ZERO,
                endpoint: None,
            },
            // auth peer
            Peer {
                public_key: wgxd_public_key,
                preshared_key: wgxd_preshared_key.clone(),
                persistent_keepalive: Duration::ZERO,
                endpoint: Some(wgxd_socket_addr),
            },
        ],
    );
    let mut spoke: Node<SocketAddr> = Node::new(
        spoke_private_key,
        vec![
            // real peer
            Peer {
                public_key: hub_public_key,
                preshared_key: preshared_key.clone(),
                persistent_keepalive: Duration::ZERO,
                endpoint: Some(wgxd_socket_addr),
            },
            // auth peer
            Peer {
                public_key: wgxd_public_key,
                preshared_key: wgxd_preshared_key.clone(),
                persistent_keepalive: Duration::ZERO,
                endpoint: Some(wgxd_socket_addr),
            },
        ],
    );
    let mut hub_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap();
    // authorize hub
    hub.advance(Instant::now()).unwrap();
    hub.send([].into(), &wgxd_public_key).unwrap();
    hub.flush(&mut hub_socket).unwrap();
    hub.fill_buf_once(&mut hub_socket).unwrap();
    hub.receive().unwrap();
    hub.flush(&mut hub_socket).unwrap();
    eprintln!("hub authorized");
    let request = RpcRequest {
        id: 1,
        body: RpcRequestBody::SetPeers([spoke_public_key].into()),
    };
    let buffer = request.encode_to_vec();
    hub.send(buffer, &wgxd_public_key).unwrap();
    hub.flush(&mut hub_socket).unwrap();
    hub.fill_buf_once(&mut hub_socket).unwrap();
    hub.receive().unwrap();
    hub.flush(&mut hub_socket).unwrap();
    eprintln!("public keys sent");
    let mut spoke_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap();
    // authorize spoke
    spoke.advance(Instant::now()).unwrap();
    spoke.send([].into(), &wgxd_public_key).unwrap();
    spoke.flush(&mut spoke_socket).unwrap();
    spoke.fill_buf_once(&mut spoke_socket).unwrap();
    spoke.receive().unwrap();
    spoke.flush(&mut spoke_socket).unwrap();
    eprintln!("spoke authorized");
    // run echo server
    let hub_thread = std::thread::Builder::new()
        .name("hub-echo-server".into())
        .spawn(move || {
            // run echo server
            loop {
                hub.advance(Instant::now()).unwrap();
                hub.fill_buf_once(&mut hub_socket).unwrap();
                if let Some((data, from)) = hub.receive().unwrap() {
                    hub.send(data, &from).unwrap();
                    hub.flush(&mut hub_socket).unwrap();
                    return;
                }
                hub.flush(&mut hub_socket).unwrap();
            }
        })
        .unwrap();
    // run echo client
    let expected_data = "hello world".as_bytes();
    let (actual_data, from) = spoke
        .send_receive_blocking(expected_data.to_vec(), &hub_public_key, &mut spoke_socket)
        .unwrap();
    assert_eq!(hub_public_key, from);
    assert_eq!(expected_data, actual_data);
    hub_thread.join().unwrap();
}
