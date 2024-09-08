use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;

use log::error;
use mio::unix::SourceFd;
use mio::Events;
use mio::Interest;
use mio::Poll;
use mio::Token;
use mio::Waker;

pub(crate) struct IpcServer {
    poll: Poll,
    fds: Vec<OwnedFd>,
}

impl IpcServer {
    pub(crate) fn new(fds: Vec<OwnedFd>) -> Result<Self, std::io::Error> {
        let poll = Poll::new()?;
        for (i, fd) in fds.iter().enumerate() {
            poll.registry().register(
                &mut SourceFd(&fd.as_raw_fd()),
                Token(i),
                Interest::READABLE,
            )?;
        }
        Ok(Self { poll, fds })
    }

    pub(crate) fn _waker(&self) -> Result<Waker, std::io::Error> {
        Waker::new(self.poll.registry(), WAKE_TOKEN)
    }

    pub(crate) fn run(&mut self) -> Result<(), std::io::Error> {
        let mut events = Events::with_capacity(self.fds.len());
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
                    Token(i) if i < self.fds.len() => {
                        // TODO
                        Ok(())
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

const WAKE_TOKEN: Token = Token(usize::MAX);
