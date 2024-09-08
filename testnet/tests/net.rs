use std::process::Command;

use testnet::NetConfig;
use testnet::Network;
use testnet::NodeConfig;

#[test]
fn net2() {
    let user_config = vec![
        UserConfig {
            tag: "first".into(),
        },
        UserConfig {
            tag: "second".into(),
        },
    ];
    let config = NetConfig {
        callback: |i, node: Vec<NodeConfig>| {
            eprintln!(
                "hello from node {} name {:?} tag {:?}",
                i, node[i].name, user_config[i].tag
            );
            Command::new("ip").args(["address"]).status()?;
            let j = match i {
                0 => 1,
                _ => 0,
            };
            Command::new("ping")
                .args(["-c", "1", &node[j].ifaddr.addr().to_string()])
                .status()?;
            Ok(())
        },
        nodes: vec![Default::default(), Default::default()],
    };
    let network = Network::new(config).unwrap();
    network.wait().unwrap();
}

struct UserConfig {
    tag: String,
}
