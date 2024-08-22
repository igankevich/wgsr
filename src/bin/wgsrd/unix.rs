use std::collections::HashMap;
use std::fs::create_dir_all;
use std::fs::remove_file;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::path::Path;

use bincode::error::DecodeError;
use mio::event::Event;
use mio::net::UnixListener;
use mio::net::UnixStream;
use mio::unix::SourceFd;
use mio::{Interest, Poll, Token};
use rand::Rng;
use rand_core::OsRng;
use wgsr::UnixEncodeDecode;
use wgsr::UnixRequest;
use wgsr::UnixRequestError;
use wgsr::UnixResponse;
use wgsr::MAX_REQUEST_SIZE;
use wgsr::MAX_RESPONSE_SIZE;

use crate::Error;
use crate::WireguardRelay;

pub(crate) struct UnixServer {
    listener: UnixListener,
    server_token: Token,
    clients: HashMap<Token, UnixClient>,
}

impl UnixServer {
    pub(crate) fn new(
        unix_socket_path: &Path,
        server_token: Token,
        poll: &mut Poll,
    ) -> Result<Self, Error> {
        if let Some(directory) = unix_socket_path.parent() {
            create_dir_all(directory)?;
        }
        let _ = remove_file(unix_socket_path);
        let mut listener = UnixListener::bind(unix_socket_path)?;
        poll.registry()
            .register(&mut listener, server_token, Interest::READABLE)?;
        Ok(Self {
            listener,
            server_token,
            clients: Default::default(),
        })
    }

    pub(crate) fn on_server_event(
        &mut self,
        token_min: usize,
        token_max: usize,
        poll: &mut Poll,
    ) -> Result<(), Error> {
        use std::collections::hash_map::Entry;
        let max_clients = token_max - token_min + 1;
        loop {
            let (mut stream, _from) = match self.listener.accept() {
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // no more connections to accept
                    break;
                }
                other => other,
            }?;
            if self.clients.len() == max_clients {
                return Err(Error::other("max no. of unix clients reached"));
            }
            loop {
                let i = OsRng.gen_range(token_min..(token_max + 1));
                if let Entry::Vacant(v) = self.clients.entry(Token(i)) {
                    poll.registry()
                        .register(&mut stream, Token(i), Interest::READABLE)?;
                    v.insert(UnixClient::new(stream)?);
                    break;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn on_client_event(
        &mut self,
        event: &Event,
        wg_relay: &mut WireguardRelay,
        poll: &mut Poll,
    ) -> Result<(), Error> {
        if event.is_error() {
            self.clients.remove(&event.token());
            return Ok(());
        }
        let client = match self.clients.get_mut(&event.token()) {
            Some(client) => client,
            None => return Ok(()),
        };
        let mut interest: Option<Interest> = None;
        if event.is_readable() {
            client.fill_buf()?;
            while let Some(request) = client.read_request()? {
                let response = match request {
                    UnixRequest::Running => UnixResponse::Running,
                    UnixRequest::Status => UnixResponse::Status(Ok(wg_relay.status())),
                    UnixRequest::Export { format } => {
                        let response = wg_relay
                            .export_config(format)
                            .map_err(UnixRequestError::map);
                        UnixResponse::Export(response)
                    }
                };
                client.send_response(&response)?;
            }
            if !client.flush()? {
                interest = Some(Interest::READABLE | Interest::WRITABLE);
            }
        }
        if event.is_writable() && client.flush()? {
            interest = Some(Interest::READABLE);
        }
        if let Some(interest) = interest {
            poll.registry()
                .reregister(&mut SourceFd(&client.fd), self.server_token, interest)?;
        }
        Ok(())
    }
}

struct UnixClient {
    fd: RawFd,
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
}

impl UnixClient {
    fn new(stream: UnixStream) -> Result<Self, Error> {
        let stream: std::os::unix::net::UnixStream = stream.into();
        let fd = stream.as_raw_fd();
        let input_stream = UnixStream::from_std(stream.try_clone()?);
        let output_stream = UnixStream::from_std(stream);
        Ok(Self {
            fd,
            reader: BufReader::with_capacity(MAX_REQUEST_SIZE, input_stream),
            writer: BufWriter::with_capacity(MAX_RESPONSE_SIZE, output_stream),
        })
    }

    fn fill_buf(&mut self) -> Result<(), Error> {
        self.reader.fill_buf()?;
        Ok(())
    }

    fn read_request(&mut self) -> Result<Option<UnixRequest>, Error> {
        match UnixRequest::decode(&mut self.reader) {
            Ok(request) => Ok(Some(request)),
            Err(DecodeError::UnexpectedEnd { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn send_response(&mut self, response: &UnixResponse) -> Result<(), Error> {
        response.encode(&mut self.writer)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<bool, Error> {
        self.writer.flush()?;
        Ok(self.writer.buffer().is_empty())
    }
}
