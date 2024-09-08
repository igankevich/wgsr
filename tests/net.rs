#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use rand_core::OsRng;
use rand_core::RngCore;
use tempfile::tempdir;
use test_bin::get_test_bin;
use testnet::NetConfig;
use testnet::Network;
use testnet::NodeConfig;

use crate::logger::Logger;
use crate::wgxd::Wgxd;

mod logger;
#[allow(dead_code)]
mod wgxd;

#[test]
fn testnet() {
    let _ = Logger::init(log::Level::Info);
    let workdir = tempdir().unwrap();
    let random_bytes: Vec<u8> = generate_random_bytes();
    std::fs::write(workdir.path().join("random-file"), random_bytes).unwrap();
    let config = NetConfig {
        callback: |context| {
            let i = context.current_node_index();
            let nodes = context.nodes();
            match i {
                RELAY_NODE_INDEX => relay_main(&nodes[i]),
                HUB_NODE_INDEX => hub_main(&nodes[RELAY_NODE_INDEX], workdir.path()),
                SPOKE_NODE_INDEX => spoke_main(&nodes[RELAY_NODE_INDEX], workdir.path()),
                _ => Err("invalid node index".into()),
            }
        },
        nodes: vec![Default::default(); 3],
    };
    let network = Network::new(config).unwrap();
    network.wait().unwrap();
}

fn relay_main(config: &NodeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let wgxd = Wgxd::with_port(RELAY_PORT.try_into().unwrap());
    wgxd.wait_until_started();
    log::info!("started relay on {}:{}", config.ifaddr.addr(), RELAY_PORT);
    sleep(Duration::from_secs(7));
    log::info!("relay exited");
    Ok(())
}

fn hub_main(relay_config: &NodeConfig, workdir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config_file = workdir.join("hub.conf");
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("init"),
            OsStr::new(format!("{}:{}", relay_config.ifaddr.addr(), RELAY_PORT).as_str())
        ])
        .status()
        .unwrap()
        .success());
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("start"),
        ])
        .status()
        .unwrap()
        .success());
    let output = get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("add-spoke"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    std::fs::write(workdir.join("spoke.conf"), output.stdout).unwrap();
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("reload"),
        ])
        .status()
        .unwrap()
        .success());
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("sync"),
        ])
        .status()
        .unwrap()
        .success());
    //Command::new("ip").args(["address"]).status().unwrap();
    //Command::new("wg").args(["show", "wgx"]).status().unwrap();
    Command::new("python3")
        .args(["-m", "http.server"])
        .current_dir(workdir)
        .spawn()
        .unwrap();
    sleep(Duration::from_secs(7));
    log::info!("hub exited");
    Ok(())
}

fn spoke_main(relay_config: &NodeConfig, workdir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    sleep(Duration::from_secs(3));
    log::info!("spoke started");
    let config_file = workdir.join("spoke.conf");
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("spoke"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("init"),
            OsStr::new(format!("{}:{}", relay_config.ifaddr.addr(), RELAY_PORT).as_str())
        ])
        .status()
        .unwrap()
        .success());
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("spoke"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("start"),
        ])
        .status()
        .unwrap()
        .success());
    eprintln!("hub");
    Command::new("cat")
        .args([workdir.join("hub.conf")])
        .status()
        .unwrap();
    eprintln!("spoke");
    Command::new("cat")
        .args([workdir.join("spoke.conf")])
        .status()
        .unwrap();
    let hub_inner_ipaddr = "10.120.0.1";
    assert!(Command::new("curl")
        .args([
            OsStr::new("--fail"),
            OsStr::new("--retry"),
            OsStr::new("3"),
            OsStr::new("--connect-timeout"),
            OsStr::new("7"),
            OsStr::new("--output"),
            workdir.join("downloaded-random-file").as_os_str(),
            OsStr::new(format!("http://{}:8000/random-file", hub_inner_ipaddr).as_str()),
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        std::fs::read(workdir.join("downloaded-random-file")).unwrap(),
        std::fs::read(workdir.join("random-file")).unwrap(),
    );
    log::info!("spoke exited");
    Ok(())
}

fn generate_random_bytes() -> Vec<u8> {
    let mut bytes = vec![0_u8; 4096];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

const RELAY_NODE_INDEX: usize = 0;
const HUB_NODE_INDEX: usize = 1;
const SPOKE_NODE_INDEX: usize = 2;
const RELAY_PORT: u16 = 8787;
