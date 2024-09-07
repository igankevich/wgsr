use ipnet::IpNet;

pub type CallbackResult = Result<(), Box<dyn std::error::Error>>;

pub struct NetConfig<F: FnOnce(usize, Vec<NodeConfig>, Vec<C>) -> CallbackResult, C: Clone = ()> {
    pub nodes: Vec<(NodeConfig, C)>,
    pub callback: F,
}

#[derive(Default, Clone)]
pub struct NodeConfig {
    /// Host name.
    pub name: String,
    pub ipaddr: IpNet,
}
