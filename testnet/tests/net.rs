use std::process::Command;

use testnet::NetConfig;
use testnet::Network;

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
        callback: |context| {
            let i = context.current_node_index();
            let node = context.current_node();
            eprintln!(
                "hello from node {} name {:?} tag {:?}",
                i, node.name, user_config[i].tag
            );
            Command::new("ip").args(["address"]).status()?;
            let j = match i {
                0 => 1,
                _ => 0,
            };
            Command::new("ping")
                .args(["-c", "1", &context.nodes()[j].ifaddr.addr().to_string()])
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
