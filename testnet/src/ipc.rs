use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;

use bincode::error::DecodeError;
use log::error;
use mio::event::Event;
use mio::unix::SourceFd;
use mio::Events;
use mio::Interest;
use mio::Poll;
use mio::Token;
use mio::Waker;
use nix::fcntl::fcntl;
use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;

use crate::IpcEncodeDecode;
use crate::IpcMessage;
use crate::IpcStateMachine;

pub(crate) struct IpcServer {
    poll: Poll,
    clients: Vec<IpcClient>,
    state: IpcStateMachine,
}

impl IpcServer {
    pub(crate) fn new(fds: Vec<(OwnedFd, OwnedFd)>) -> Result<Self, std::io::Error> {
        let poll = Poll::new()?;
        let mut clients = Vec::with_capacity(fds.len());
        for (i, (in_fd, out_fd)) in fds.into_iter().enumerate() {
            fcntl(in_fd.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            fcntl(out_fd.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            poll.registry().register(
                &mut SourceFd(&in_fd.as_raw_fd()),
                Token(i),
                Interest::READABLE,
            )?;
            clients.push(IpcClient::new(in_fd, out_fd));
        }
        let num_nodes = clients.len();
        Ok(Self {
            poll,
            clients,
            state: IpcStateMachine::new(num_nodes),
        })
    }

    pub(crate) fn _waker(&self) -> Result<Waker, std::io::Error> {
        Waker::new(self.poll.registry(), WAKE_TOKEN)
    }

    pub(crate) fn run(&mut self) -> Result<(), std::io::Error> {
        let mut events = Events::with_capacity(self.clients.len());
        let n = self.clients.len();
        loop {
            events.clear();
            match self.poll.poll(&mut events, None) {
                Ok(()) => Ok(()),
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(()),
                other => other,
            }?;
            for event in events.iter() {
                let ret = match event.token() {
                    WAKE_TOKEN => return Ok(()),
                    // input fds
                    token @ Token(i) if (0..n).contains(&i) => {
                        self.clients[i].on_event(event, token, &mut self.poll, &mut self.state, i)
                    }
                    // output fds
                    token @ Token(i) if (n..(n + n)).contains(&i) => {
                        let i = i - n;
                        self.clients[i].on_event(event, token, &mut self.poll, &mut self.state, i)
                    }
                    Token(i) => Err(std::io::Error::other(format!("unknown event {}", i))),
                };
                if let Err(e) = ret {
                    error!("ipc server error: {}", e);
                }
            }
        }
    }
}

struct IpcClient {
    reader: BufReader<File>,
    writer: BufWriter<File>,
}

impl IpcClient {
    fn new(in_fd: OwnedFd, out_fd: OwnedFd) -> Self {
        Self {
            reader: BufReader::with_capacity(MAX_MESSAGE_SIZE, in_fd.into()),
            writer: BufWriter::with_capacity(MAX_MESSAGE_SIZE, out_fd.into()),
        }
    }

    fn on_event(
        &mut self,
        event: &Event,
        token: Token,
        poll: &mut Poll,
        state: &mut IpcStateMachine,
        node_index: usize,
    ) -> Result<(), std::io::Error> {
        let mut interest: Option<Interest> = None;
        if event.is_readable() {
            self.fill_buf()?;
            while let Some(message) = self.receive_message()? {
                state
                    .on_message(message, node_index)
                    .map_err(std::io::Error::other)?;
            }
            if !self.flush()? {
                interest = Some(Interest::READABLE | Interest::WRITABLE);
            }
        }
        if event.is_writable() && self.flush()? {
            interest = Some(Interest::READABLE);
        }
        if let Some(interest) = interest {
            poll.registry().reregister(
                &mut SourceFd(&self.writer.get_ref().as_raw_fd()),
                token,
                interest,
            )?;
        }
        Ok(())
    }

    fn fill_buf(&mut self) -> Result<(), std::io::Error> {
        self.reader.fill_buf()?;
        Ok(())
    }

    fn flush(&mut self) -> Result<bool, std::io::Error> {
        self.writer.flush()?;
        Ok(self.writer.buffer().is_empty())
    }

    fn receive_message(&mut self) -> Result<Option<IpcMessage>, std::io::Error> {
        match IpcMessage::decode(&mut self.reader) {
            Ok(message) => Ok(Some(message)),
            Err(DecodeError::UnexpectedEnd { .. }) => Ok(None),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }

    fn _send_message(&mut self, message: &IpcMessage) -> Result<(), std::io::Error> {
        message
            .encode(&mut self.writer)
            .map_err(std::io::Error::other)?;
        Ok(())
    }
}

const WAKE_TOKEN: Token = Token(usize::MAX);
pub(crate) const MAX_MESSAGE_SIZE: usize = 4096 * 16;
