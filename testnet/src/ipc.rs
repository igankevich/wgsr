use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;

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

pub(crate) struct IpcServer {
    poll: Poll,
    clients: Vec<IpcClient>,
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
        Ok(Self { poll, clients })
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
                        self.clients[i].on_event(event, token, &mut self.poll)
                    }
                    // output fds
                    token @ Token(i) if (n..(n + n)).contains(&i) => {
                        let i = i - n;
                        self.clients[i].on_event(event, token, &mut self.poll)
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
            reader: BufReader::with_capacity(MAX_REQUEST_SIZE, in_fd.into()),
            writer: BufWriter::with_capacity(MAX_RESPONSE_SIZE, out_fd.into()),
        }
    }

    fn on_event(
        &mut self,
        event: &Event,
        token: Token,
        poll: &mut Poll,
    ) -> Result<(), std::io::Error> {
        let mut interest: Option<Interest> = None;
        if event.is_readable() {
            self.reader.fill_buf()?;
            // TODO
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

    fn flush(&mut self) -> Result<bool, std::io::Error> {
        self.writer.flush()?;
        Ok(self.writer.buffer().is_empty())
    }
}

const WAKE_TOKEN: Token = Token(usize::MAX);
const MAX_REQUEST_SIZE: usize = 4096 * 16;
const MAX_RESPONSE_SIZE: usize = MAX_REQUEST_SIZE;
