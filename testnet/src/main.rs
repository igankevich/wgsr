use std::process::Command;
use std::process::ExitCode;

use testnet::NetConfig;
use testnet::Network;
use testnet::NodeConfig;

fn main() -> ExitCode {
    match do_main() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn do_main() -> Result<(), Box<dyn std::error::Error>> {
    let config = NetConfig {
        callback: |i, node: Vec<NodeConfig>, user: Vec<UserConfig>| {
            eprintln!(
                "hello from node {} name {:?} tag {:?}",
                i, node[i].name, user[i].tag
            );
            Command::new("ip").args(["address"]).status()?;
            let j = match i {
                0 => 1,
                _ => 0,
            };
            Command::new("ping")
                .args(["-c", "1", &node[j].ipaddr.addr().to_string()])
                .status()?;
            Ok(())
        },
        nodes: vec![
            (
                Default::default(),
                UserConfig {
                    tag: "first".into(),
                },
            ),
            (
                Default::default(),
                UserConfig {
                    tag: "second".into(),
                },
            ),
        ],
    };
    let network = Network::new(config)?;
    network.wait()?;
    Ok(())
}

#[derive(Default, Clone)]
struct UserConfig {
    tag: String,
}
