use ipnet::IpNet;

use crate::IpcClient;
use crate::IpcMessage;

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
    pub(crate) ipc_client: IpcClient,
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

    /// Advance the global state.
    ///
    /// Synchronize with all other nodes.
    /// Submit arbitrary `data` as a part of the global state.
    pub fn send(&mut self, data: Vec<u8>) -> Result<(), std::io::Error> {
        self.ipc_client.send(&IpcMessage::Send(data))?;
        self.ipc_client.flush()?;
        self.ipc_client.fill_buf()?;
        let response = self
            .ipc_client
            .receive()?
            .ok_or_else(|| std::io::Error::other("no response"))?;
        if !matches!(response, IpcMessage::Wait) {
            return Err(std::io::Error::other("invalid response"));
        }
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Vec<u8>, std::io::Error> {
        self.ipc_client.send(&IpcMessage::Receive)?;
        self.ipc_client.flush()?;
        self.ipc_client.fill_buf()?;
        let response = self
            .ipc_client
            .receive()?
            .ok_or_else(|| std::io::Error::other("no response"))?;
        match response {
            IpcMessage::Send(data) => Ok(data),
            _ => Err(std::io::Error::other("invalid response")),
        }
    }

    pub fn wait(&mut self) -> Result<(), std::io::Error> {
        self.ipc_client.send(&IpcMessage::Wait)?;
        self.ipc_client.flush()?;
        self.ipc_client.fill_buf()?;
        let response = self
            .ipc_client
            .receive()?
            .ok_or_else(|| std::io::Error::other("no response"))?;
        if !matches!(response, IpcMessage::Wait) {
            return Err(std::io::Error::other("invalid response"));
        }
        Ok(())
    }
}
