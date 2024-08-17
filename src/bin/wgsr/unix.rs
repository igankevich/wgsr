use std::io::BufReader;
use std::io::BufWriter;
use std::os::unix::net::UnixStream;
use std::path::Path;

use wgsr::EncodeDecode;
use wgsr::Request;
use wgsr::Response;
use wgsr::MAX_REQUEST_SIZE;
use wgsr::MAX_RESPONSE_SIZE;

use crate::format_error;
use crate::Error;

pub(crate) struct UnixClient {
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
}

impl UnixClient {
    pub(crate) fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let stream = UnixStream::connect(path.as_ref()).map_err(|e| {
            format_error!("failed to connect to `{}`: {}", path.as_ref().display(), e)
        })?;
        let input_stream = stream.try_clone()?;
        let output_stream = stream;
        Ok(Self {
            reader: BufReader::with_capacity(MAX_RESPONSE_SIZE, input_stream),
            writer: BufWriter::with_capacity(MAX_REQUEST_SIZE, output_stream),
        })
    }

    pub(crate) fn call(&mut self, request: Request) -> Result<Response, Error> {
        request.encode(&mut self.writer)?;
        let response = Response::decode(&mut self.reader)?;
        Ok(response)
    }
}
