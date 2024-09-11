use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
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
use mio_pidfd::PidFd;
use nix::errno::Errno;
use nix::fcntl::fcntl;
use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;
use nix::sys::wait::waitid;
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;

use crate::IpcEncodeDecode;
use crate::IpcMessage;
use crate::IpcStateMachine;

pub(crate) struct IpcServer {
    poll: Poll,
    clients: Vec<IpcClient>,
    pid_fds: Vec<PidFd>,
    output_readers: Vec<OutputReader>,
    state: IpcStateMachine,
    finished: HashMap<usize, bool>,
}

impl IpcServer {
    pub(crate) fn new(
        fds: Vec<(OwnedFd, OwnedFd, PidFd, OwnedFd, String)>,
    ) -> Result<Self, std::io::Error> {
        let poll = Poll::new()?;
        let mut clients = Vec::with_capacity(fds.len());
        let mut pid_fds = Vec::with_capacity(fds.len());
        let mut output_readers = Vec::with_capacity(fds.len());
        for (i, (in_fd, out_fd, pid_fd, output_fd, node_name)) in fds.into_iter().enumerate() {
            fcntl(in_fd.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            fcntl(out_fd.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            fcntl(output_fd.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            poll.registry().register(
                &mut SourceFd(&in_fd.as_raw_fd()),
                fd_in_token(i),
                Interest::READABLE,
            )?;
            poll.registry().register(
                &mut SourceFd(&pid_fd.as_raw_fd()),
                pid_fd_token(i),
                Interest::READABLE,
            )?;
            poll.registry().register(
                &mut SourceFd(&output_fd.as_raw_fd()),
                output_fd_token(i),
                Interest::READABLE,
            )?;
            clients.push(IpcClient::new(in_fd, out_fd));
            pid_fds.push(pid_fd);
            output_readers.push(OutputReader::new(output_fd, node_name));
        }
        let num_nodes = clients.len();
        Ok(Self {
            poll,
            clients,
            pid_fds,
            output_readers,
            state: IpcStateMachine::new(num_nodes),
            finished: Default::default(),
        })
    }

    pub(crate) fn _waker(&self) -> Result<Waker, std::io::Error> {
        Waker::new(self.poll.registry(), WAKE_TOKEN)
    }

    pub(crate) fn run(&mut self) -> Result<(), std::io::Error> {
        let mut events = Events::with_capacity(self.clients.len());
        let n = self.clients.len();
        while self.finished.len() != n {
            events.clear();
            match self.poll.poll(&mut events, None) {
                Ok(()) => Ok(()),
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(()),
                other => other,
            }?;
            for event in events.iter() {
                let ret = match event.token() {
                    WAKE_TOKEN => return Ok(()),
                    token @ Token(i) if (0..(NUM_FDS * n)).contains(&i) => {
                        let i = token_to_client_index(token);
                        match FdKind::new(token) {
                            FdKind::In | FdKind::Out => self.on_event(event, token, i),
                            FdKind::Pid => {
                                self.handle_finished(event, i);
                                if self.process_failed(i)? {
                                    return Err(std::io::Error::other(format!("node {i} failed")));
                                }
                                Ok(())
                            }
                            FdKind::Output => {
                                self.handle_finished(event, i);
                                self.on_process_output(event, i)?;
                                Ok(())
                            }
                        }
                    }
                    Token(i) => Err(std::io::Error::other(format!("unknown event {}", i))),
                };
                if let Err(e) = ret {
                    error!("ipc server error: {}", e);
                }
            }
        }
        Ok(())
    }

    fn handle_finished(&mut self, event: &Event, i: usize) {
        if event.is_error() {
            self.finished.insert(i, false);
        }
        if event.is_read_closed() || event.is_write_closed() {
            self.finished.insert(i, true);
        }
    }

    fn on_event(
        &mut self,
        event: &Event,
        writer_token: Token,
        i: usize,
    ) -> Result<(), std::io::Error> {
        let mut interest: Option<Interest> = None;
        if event.is_readable() {
            self.clients[i].fill_buf()?;
            while let Some(message) = self.clients[i].receive()? {
                self.state
                    .on_message(message, i, &mut self.clients, writer_token, &mut self.poll)
                    .map_err(std::io::Error::other)?;
            }
            if !self.clients[i].flush()? {
                interest = Some(Interest::WRITABLE);
            }
        }
        let client = &mut self.clients[i];
        if event.is_writable() && client.flush()? {
            interest = Some(Interest::READABLE);
        }
        match interest {
            Some(Interest::READABLE) => self
                .poll
                .registry()
                .deregister(&mut SourceFd(&client.writer.get_ref().as_raw_fd()))?,
            Some(Interest::WRITABLE) => {
                self.poll.registry().reregister(
                    &mut SourceFd(&client.writer.get_ref().as_raw_fd()),
                    writer_token,
                    Interest::WRITABLE,
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn process_failed(&mut self, i: usize) -> Result<bool, std::io::Error> {
        use nix::sys::wait::Id;
        let status = match waitid(
            Id::PIDFd(unsafe { BorrowedFd::borrow_raw(self.pid_fds[i].as_raw_fd()) }),
            WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
        ) {
            Ok(status) => Some(status),
            Err(Errno::EINVAL) => None,
            Err(e) => return Err(e.into()),
        };
        let finished = match status {
            Some(WaitStatus::Exited(..)) => true,
            Some(WaitStatus::Signaled(..)) => true,
            Some(_) => false,
            None => true,
        };
        if finished {
            self.finished.insert(i, true);
        }
        match status {
            Some(status) => Ok(status_is_failure(status)),
            None => Ok(false),
        }
    }

    fn on_process_output(&mut self, event: &Event, i: usize) -> Result<(), std::io::Error> {
        if event.is_readable() {
            self.output_readers[i].print_lines()?;
        }
        if event.is_error() || event.is_read_closed() || event.is_write_closed() {
            self.output_readers[i].print_lines()?;
            self.output_readers[i].print_remaining()?;
        }
        Ok(())
    }
}

pub(crate) struct IpcClient {
    reader: BufReader<File>,
    writer: BufWriter<File>,
}

impl IpcClient {
    pub(crate) fn new(in_fd: OwnedFd, out_fd: OwnedFd) -> Self {
        Self {
            reader: BufReader::with_capacity(MAX_MESSAGE_SIZE, in_fd.into()),
            writer: BufWriter::with_capacity(MAX_MESSAGE_SIZE, out_fd.into()),
        }
    }

    pub(crate) fn fill_buf(&mut self) -> Result<(), std::io::Error> {
        self.reader.fill_buf()?;
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<bool, std::io::Error> {
        self.writer.flush()?;
        Ok(self.writer.buffer().is_empty())
    }

    pub(crate) fn receive(&mut self) -> Result<Option<IpcMessage>, std::io::Error> {
        match IpcMessage::decode(&mut self.reader) {
            Ok(message) => Ok(Some(message)),
            Err(DecodeError::UnexpectedEnd { .. }) => Ok(None),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }

    pub(crate) fn send(&mut self, message: &IpcMessage) -> Result<(), std::io::Error> {
        message
            .encode(&mut self.writer)
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    pub(crate) fn send_finalize(
        &mut self,
        writer_token: Token,
        poll: &mut Poll,
    ) -> Result<(), std::io::Error> {
        if !self.flush()? {
            poll.registry().reregister(
                &mut SourceFd(&self.writer.get_ref().as_raw_fd()),
                writer_token,
                Interest::WRITABLE,
            )?;
        }
        Ok(())
    }
}

struct OutputReader {
    reader: BufReader<File>,
    line: LineBuffer,
}

impl OutputReader {
    pub(crate) fn new(in_fd: OwnedFd, name: String) -> Self {
        Self {
            reader: BufReader::with_capacity(OUTPUT_BUFFER_SIZE, in_fd.into()),
            line: LineBuffer::new(format!("{name}: ")),
        }
    }

    pub(crate) fn print_lines(&mut self) -> Result<(), std::io::Error> {
        let mut buf = self.reader.fill_buf()?;
        let buf_len = buf.len();
        while let Some(mut i) = buf.iter().position(|ch| *ch == b'\n') {
            i += 1;
            self.line.append(&buf[..i]);
            self.line.print()?;
            buf = &buf[i..];
        }
        if !buf.is_empty() {
            self.line.append(buf);
        }
        self.reader.consume(buf_len);
        Ok(())
    }

    pub(crate) fn print_remaining(&mut self) -> Result<(), std::io::Error> {
        if !self.line.is_empty() {
            self.line.append("⏎\n".as_bytes());
            self.line.print()?;
        }
        Ok(())
    }
}

struct LineBuffer {
    line: Vec<u8>,
    prefix: String,
}

impl LineBuffer {
    fn new(prefix: String) -> Self {
        Self {
            line: Vec::new(),
            prefix,
        }
    }

    fn is_empty(&self) -> bool {
        self.line.is_empty()
    }

    fn append(&mut self, buf: &[u8]) {
        if self.line.is_empty() {
            self.line.extend_from_slice(self.prefix.as_bytes());
        }
        self.line.extend_from_slice(buf);
    }

    fn print(&mut self) -> Result<(), std::io::Error> {
        std::io::stderr().write_all(&self.line)?;
        self.line.clear();
        Ok(())
    }
}

fn fd_in_token(i: usize) -> Token {
    Token(NUM_FDS * i)
}

fn pid_fd_token(i: usize) -> Token {
    Token(NUM_FDS * i + 2)
}

fn output_fd_token(i: usize) -> Token {
    Token(NUM_FDS * i + 3)
}

fn token_to_client_index(token: Token) -> usize {
    token.0 / NUM_FDS
}

enum FdKind {
    In,
    Out,
    Pid,
    Output,
}

impl FdKind {
    fn new(token: Token) -> Self {
        match token.0 % NUM_FDS {
            0 => Self::In,
            1 => Self::Out,
            2 => Self::Pid,
            _ => Self::Output,
        }
    }
}

fn status_is_failure(status: WaitStatus) -> bool {
    match status {
        WaitStatus::Exited(_, code) if code != 0 => true,
        WaitStatus::Signaled(..) => true,
        _ => false,
    }
}

const WAKE_TOKEN: Token = Token(usize::MAX);
const NUM_FDS: usize = 4;
pub(crate) const MAX_MESSAGE_SIZE: usize = 4096 * 16;
pub(crate) const OUTPUT_BUFFER_SIZE: usize = 4096 * 16;
