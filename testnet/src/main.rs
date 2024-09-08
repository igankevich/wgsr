use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::ExitCode;

use clap::Parser;
use testnet::NetConfig;
use testnet::Network;
use testnet::NodeConfig;

#[derive(Parser)]
#[command(
    about = "Testnet — run your distributed application in a test network.",
    long_about = None,
    trailing_var_arg = true,
)]
struct Args {
    /// Print version.
    #[clap(long, action)]
    version: bool,
    #[clap(short = 'n', long, default_value = "2")]
    nodes: usize,
    /// Command to run.
    program: OsString,
    /// Command arguments.
    #[clap(allow_hyphen_values = true)]
    args: Vec<OsString>,
}

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
    let args = Args::parse();
    if args.version {
        println!("{}", env!("VERSION"));
        return Ok(());
    }
    let config = NetConfig {
        callback: |i, node: Vec<NodeConfig>| {
            Err(Command::new(&args.program)
                .args(&args.args)
                .env("TESTNET_NODE_INDEX", i.to_string())
                .env("TESTNET_NODE_NAME", &node[i].name)
                .env("TESTNET_NODE_IFADDR", node[i].ifaddr.to_string())
                .env("TESTNET_NODE_IPADDR", node[i].ifaddr.addr().to_string())
                .exec()
                .into())
        },
        nodes: vec![Default::default(); args.nodes],
    };
    let network = Network::new(config)?;
    network.wait()?;
    Ok(())
}
