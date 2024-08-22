use mio::Events;
use mio::Poll;
use mio::Token;
use mio::Waker;
use static_assertions::const_assert;

use crate::format_error;
use crate::Config;
use crate::Error;
use crate::UnixServer;
use crate::WireguardRelay;

pub(crate) struct Dispatcher {
    poll: Poll,
    wg_relay: WireguardRelay,
    unix_server: UnixServer,
}

impl Dispatcher {
    pub(crate) fn new(config: Config) -> Result<Self, Error> {
        let mut poll = Poll::new()?;
        let unix_server = UnixServer::new(
            config.unix_socket_path.as_path(),
            UNIX_SERVER_TOKEN,
            &mut poll,
        )?;
        let wg_relay = WireguardRelay::new(config, UDP_SERVER_TOKEN, &mut poll)?;
        Ok(Self {
            poll,
            wg_relay,
            unix_server,
        })
    }

    pub(crate) fn waker(&self) -> Result<Waker, Error> {
        Ok(Waker::new(self.poll.registry(), WAKE_TOKEN)?)
    }

    pub(crate) fn run(mut self) -> Result<(), Error> {
        let mut events = Events::with_capacity(MAX_EVENTS);
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
                    UDP_SERVER_TOKEN => {
                        if event.is_readable() {
                            self.wg_relay.on_event()
                        } else {
                            Ok(())
                        }
                    }
                    UNIX_SERVER_TOKEN => {
                        if event.is_readable() {
                            self.unix_server.on_server_event(
                                UNIX_TOKEN_MIN,
                                UNIX_TOKEN_MAX,
                                &mut self.poll,
                            )
                        } else {
                            Ok(())
                        }
                    }
                    Token(i) if (UNIX_TOKEN_MIN..=UNIX_TOKEN_MAX).contains(&i) => self
                        .unix_server
                        .on_client_event(event, &mut self.wg_relay, &mut self.poll),
                    Token(i) => Err(format_error!("unknown event {}", i)),
                };
                if let Err(e) = ret {
                    eprintln!("{}", e);
                }
            }
        }
    }
}

const MAX_EVENTS: usize = 1024;
const WAKE_TOKEN: Token = Token(usize::MAX);
const UDP_SERVER_TOKEN: Token = Token(usize::MAX - 1);
const UNIX_SERVER_TOKEN: Token = Token(usize::MAX - 2);
const MAX_UNIX_CLIENTS: usize = 1000;
const UNIX_TOKEN_MAX: usize = usize::MAX - 3;
const UNIX_TOKEN_MIN: usize = UNIX_TOKEN_MAX + 1 - MAX_UNIX_CLIENTS;

const_assert!(UNIX_TOKEN_MIN <= UNIX_TOKEN_MAX);
const_assert!(UNIX_TOKEN_MAX < UNIX_SERVER_TOKEN.0);
const_assert!(UDP_SERVER_TOKEN.0 < WAKE_TOKEN.0);
const_assert!(UNIX_SERVER_TOKEN.0 < UDP_SERVER_TOKEN.0);
const_assert!(MAX_UNIX_CLIENTS == UNIX_TOKEN_MAX - UNIX_TOKEN_MIN + 1);
