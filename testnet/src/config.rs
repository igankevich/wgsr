use std::fmt::Display;

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
    pub(crate) step_name: Option<String>,
    pub(crate) step: usize,
}

impl Context {
    pub fn current_node_index(&self) -> usize {
        self.node_index
    }

    pub fn current_node_name(&self) -> &str {
        self.nodes[self.node_index].name.as_str()
    }

    pub fn current_node(&self) -> &NodeConfig {
        &self.nodes[self.node_index]
    }

    pub fn nodes(&self) -> &[NodeConfig] {
        &self.nodes
    }

    pub fn step(&mut self, name: impl Display) {
        self.step_name = Some(format!("\"{name}\""));
    }

    /// Advance the global state.
    ///
    /// Synchronize with all other nodes.
    /// Submit arbitrary `data` as a part of the global state.
    pub fn send(&mut self, data: Vec<u8>) -> Result<(), std::io::Error> {
        self.next_step();
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
        self.print_step();
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

    fn next_step(&mut self) {
        self.step += 1;
        if self.step_name.is_none() {
            self.step_name = Some(self.step.to_string());
        }
    }

    fn print_step(&mut self) {
        if let Some(step) = self.step_name.take() {
            log::info!("step {step}: ok");
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Some(step) = self.step_name.take() {
            log::error!("step {step}: failed");
        }
    }
}
