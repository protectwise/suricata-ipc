use crate::errors::Error;
use crate::eve::json;

use crate::config::ReaderMessageType;
use log::*;
use pin_project::pin_project;
use smol::io::AsyncRead;
use smol::stream::Stream;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFAULT_BUFFER_SIZE: usize = 131_070;

type AsyncStream = smol::Async<std::os::unix::net::UnixStream>;

#[pin_project]
pub struct EveReader<T> {
    path: PathBuf,
    message_type: ReaderMessageType,
    #[pin]
    inner: AsyncStream,
    buf: Vec<u8>,
    buffer_size: usize,
    last_offset: usize,
    marker: std::marker::PhantomData<T>,
    complete: bool,
}

impl<T> EveReader<T> {
    pub fn new(path: PathBuf, message_type: ReaderMessageType, v: AsyncStream) -> Self {
        EveReader::with_capacity(path, message_type, v, DEFAULT_BUFFER_SIZE)
    }

    pub fn with_capacity(
        path: PathBuf,
        message_type: ReaderMessageType,
        v: AsyncStream,
        sz: usize,
    ) -> Self {
        Self {
            path: path,
            message_type: message_type,
            inner: v,
            buf: Vec::with_capacity(sz),
            last_offset: 0,
            marker: std::marker::PhantomData,
            complete: false,
            buffer_size: sz,
        }
    }
}

impl<T> Stream for EveReader<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    type Item = Result<Vec<T>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if *this.complete {
            return Poll::Ready(None);
        }

        let last_offset = *this.last_offset;
        if this.buf.len() != *this.buffer_size {
            this.buf
                .resize_with(*this.buffer_size - last_offset, Default::default);
        }
        match smol::ready!(this
            .inner
            .as_mut()
            .poll_read(cx, &mut this.buf[last_offset..]))
        {
            Err(e) => {
                *this.complete = true;
                Poll::Ready(Some(Err(Error::from(e))))
            }
            Ok(bytes_read) => {
                trace!(
                    "{} (path: {:?}): Read {}B",
                    this.message_type,
                    this.path,
                    bytes_read
                );

                if bytes_read == 0 {
                    *this.complete = true;
                    return Poll::Ready(None);
                }

                let total_size = last_offset + bytes_read;
                let read_slice = &this.buf[..total_size];

                trace!(
                    "{} (path: {:?}): Collecting eve messages from {} bytes",
                    this.message_type,
                    this.path,
                    total_size
                );
                match json::JsonParser::parse(read_slice) {
                    Err(e) => {
                        *this.complete = true;
                        Poll::Ready(Some(Err(e)))
                    }
                    Ok((rem, msgs)) => {
                        debug!(
                            "{} (path: {:?}): Collected {} eve messages",
                            this.message_type,
                            this.path,
                            msgs.len()
                        );

                        *this.last_offset = rem.len();

                        let bytes_parsed = total_size - rem.len();
                        let mut to_keep = this.buf.split_off(bytes_parsed);
                        std::mem::swap(this.buf, &mut to_keep);
                        this.buf.reserve(*this.buffer_size - *this.last_offset);

                        let msgs: Result<Vec<_>, _> = msgs
                            .iter()
                            .map(|v| {
                                serde_json::from_slice::<T>(v.as_slice()).map_err(|e| {
                                    debug!(
                                        "{} (path: {:?}): Failed to decode: {}",
                                        this.message_type,
                                        this.path,
                                        String::from_utf8(v.clone()).unwrap()
                                    );
                                    Error::SerdeJson(e)
                                })
                            })
                            .collect();

                        Poll::Ready(Some(msgs))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::EveMessage;
    use smol::io::AsyncWriteExt;
    use smol::stream::StreamExt;

    #[test]
    fn reads_eve() {
        let _ = env_logger::try_init();

        let (server, client) =
            std::os::unix::net::UnixStream::pair().expect("Could not build pair");
        let mut server = smol::Async::new(server).unwrap();

        let send_complete = async move {
            let bytes = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#.as_bytes();

            server.write_all(bytes).await.expect("Failed to send");
            server.flush().await.expect("Failed to flush");

            info!("Send complete");
        };

        smol::spawn(send_complete).detach();

        let client = smol::Async::new(client).unwrap();
        let alerts: Result<Vec<Vec<EveMessage>>, Error> = smol::block_on(
            EveReader::new(PathBuf::default(), ReaderMessageType::Alert, client).try_collect(),
        );
        let alerts: Vec<_> = alerts.unwrap().into_iter().flat_map(|v| v).collect();

        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn reads_partial_eve() {
        let _ = env_logger::try_init();

        let (server, client) =
            std::os::unix::net::UnixStream::pair().expect("Could not build pair");
        let mut server = smol::Async::new(server).unwrap();

        let send_complete = async move {
            let bytes = vec![
                r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-"#.as_bytes(),
                r#"18T10:48:14.622822-0700"}}{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip""#.as_bytes(),
                r#":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#.as_bytes(),
            ];
            for b in bytes {
                let f = server.write_all(b);

                f.await.expect("Failed to send");
            }

            info!("Send complete");
        };

        smol::spawn(send_complete).detach();

        info!("Waiting for alerts");

        let client = smol::Async::new(client).unwrap();
        let alerts: Result<Vec<Vec<EveMessage>>, Error> = smol::block_on(
            EveReader::new(PathBuf::default(), ReaderMessageType::Alert, client).try_collect(),
        );
        let alerts: Vec<_> = alerts.unwrap().into_iter().flat_map(|v| v).collect();

        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn reads_single_eve_event() {
        let _ = env_logger::try_init();

        let (server, client) =
            std::os::unix::net::UnixStream::pair().expect("Could not build pair");
        let mut server = smol::Async::new(server).unwrap();

        let send_complete = async move {
            let bytes = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#.as_bytes();
            let f = server.write_all(bytes);

            f.await.expect("Failed to send");

            info!("Send complete");
        };

        smol::spawn(send_complete).detach();

        info!("Waiting for alerts");

        let client = smol::Async::new(client).unwrap();
        let alerts: Result<Vec<Vec<EveMessage>>, Error> = smol::block_on(
            EveReader::new(PathBuf::default(), ReaderMessageType::Alert, client).try_collect(),
        );
        let alerts: Vec<_> = alerts.unwrap().into_iter().flat_map(|v| v).collect();

        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn reads_multiple_eve_events() {
        let _ = env_logger::try_init();

        let (server, client) =
            std::os::unix::net::UnixStream::pair().expect("Could not build pair");
        let mut server = smol::Async::new(server).unwrap();

        let send_complete = async move {
            let bytes = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#.as_bytes();
            let f = server.write_all(bytes);

            f.await.expect("Failed to send");

            let f = server.write_all(bytes);

            f.await.expect("Failed to send");

            info!("Send complete");
        };

        smol::spawn(send_complete).detach();

        info!("Waiting for alerts");

        let client = smol::Async::new(client).unwrap();
        let alerts: Result<Vec<Vec<EveMessage>>, Error> = smol::block_on(
            EveReader::new(PathBuf::default(), ReaderMessageType::Alert, client).try_collect(),
        );
        let alerts: Vec<_> = alerts.unwrap().into_iter().flat_map(|v| v).collect();

        assert_eq!(alerts.len(), 2);
    }
}
