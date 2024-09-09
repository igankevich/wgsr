use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use crate::BroadcastPayload;
use crate::IpcMessage;

pub(crate) struct IpcStateMachine {
    num_nodes: usize,
    /// Node index of the initiator.
    broadcast_initiator: Option<usize>,
    broadcasts: HashMap<usize, Broadcast>,
}

impl IpcStateMachine {
    pub(crate) fn new(num_nodes: usize) -> Self {
        Self {
            num_nodes,
            broadcast_initiator: None,
            broadcasts: Default::default(),
        }
    }

    pub(crate) fn on_message(
        &mut self,
        message: IpcMessage,
        from_node_index: usize,
    ) -> Result<(), IpcStateMachineError> {
        match message {
            IpcMessage::Send(payload) => {
                if let Some(i) = self.broadcast_initiator {
                    return Err(IpcStateMachineError(format!(
                        "another broadcast from node `{}` is in progress",
                        i
                    )));
                }
                self.insert_broadcast(from_node_index, Broadcast::Send(payload))?;
                self.broadcast_initiator = Some(from_node_index);
            }
            IpcMessage::Receive => {
                self.insert_broadcast(from_node_index, Broadcast::Receive)?;
            }
            IpcMessage::Wait => {
                self.insert_broadcast(from_node_index, Broadcast::Wait)?;
            }
        }
        if self.broadcasts.len() == self.num_nodes {
            self.finalize_broadcast()?;
        }
        Ok(())
    }

    fn insert_broadcast(
        &mut self,
        i: usize,
        broadcast: Broadcast,
    ) -> Result<(), IpcStateMachineError> {
        use std::collections::hash_map::Entry;
        match self.broadcasts.entry(i) {
            Entry::Vacant(v) => {
                v.insert(broadcast);
                Ok(())
            }
            Entry::Occupied(_) => Err(IpcStateMachineError(
                "only one message per broadcast is permitted".into(),
            )),
        }
    }

    fn finalize_broadcast(&mut self) -> Result<(), IpcStateMachineError> {
        let _initiator = match self.broadcast_initiator {
            Some(initiator) => initiator,
            None => {
                return Err(IpcStateMachineError(
                    "broadcast initiator is missing".into(),
                ))
            }
        };
        // TODO
        self.broadcasts.clear();
        self.broadcast_initiator = None;
        Ok(())
    }
}

#[derive(Clone)]
enum Broadcast {
    Send(BroadcastPayload),
    Receive,
    Wait,
}

pub(crate) struct IpcStateMachineError(pub(crate) String);

impl Display for IpcStateMachineError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for IpcStateMachineError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for IpcStateMachineError {}
