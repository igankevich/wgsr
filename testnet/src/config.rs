use ipnet::IpNet;

pub type CallbackResult = Result<(), Box<dyn std::error::Error>>;

pub struct NetConfig<F: FnOnce(usize, Vec<NodeConfig>) -> CallbackResult> {
    pub nodes: Vec<NodeConfig>,
    pub callback: F,
}

#[derive(Default, Clone)]
pub struct NodeConfig {
    /// Host name.
    pub name: String,
    pub ifaddr: IpNet,
}
