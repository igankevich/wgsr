use ipnet::IpNet;

pub type CallbackResult = Result<(), Box<dyn std::error::Error>>;

pub struct NetConfig<F: FnOnce(Context) -> CallbackResult> {
    pub nodes: Vec<NodeConfig>,
    pub callback: F,
}

#[derive(Default, Clone)]
pub struct NodeConfig {
    /// Host name.
    pub name: String,
    pub ifaddr: IpNet,
}

/// Execution context.
pub struct Context {
    /// Index of the current node.
    pub(crate) node_index: usize,
    /// Node configuration of all nodes.
    pub(crate) nodes: Vec<NodeConfig>,
}

impl Context {
    pub fn current_node_index(&self) -> usize {
        self.node_index
    }

    pub fn current_node(&self) -> &NodeConfig {
        &self.nodes[self.node_index]
    }

    pub fn nodes(&self) -> &[NodeConfig] {
        &self.nodes
    }
}
