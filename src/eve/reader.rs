use crate::errors::Error;
use crate::eve::json;

use futures::{AsyncRead, Stream};
use log::*;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

const BUFFER_SIZE: usize = 131_070;

type AsyncStream = smol::Async<std::os::unix::net::UnixStream>;

#[pin_project]
pub struct EveReader<T> {
    #[pin]
    inner: AsyncStream,
    buf: Vec<u8>,
    last_offset: usize,
    marker: std::marker::PhantomData<T>,
    complete: bool,
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
        if this.buf.len() != BUFFER_SIZE {
            this.buf
                .resize_with(BUFFER_SIZE - last_offset, Default::default);
        }
        match futures::ready!(this
            .inner
            .as_mut()
            .poll_read(cx, &mut this.buf[last_offset..]))
        {
            Err(e) => {
                *this.complete = true;
                Poll::Ready(Some(Err(Error::from(e))))
            }
            Ok(bytes_read) => {
                trace!("Read {}B", bytes_read);

                if bytes_read == 0 {
                    *this.complete = true;
                    return Poll::Ready(None);
                }

                let total_size = last_offset + bytes_read;
                let read_slice = &this.buf[..total_size];

                trace!("Collecting eve messages from {} bytes", total_size);
                match json::JsonParser::parse(read_slice) {
                    Err(e) => {
                        *this.complete = true;
                        Poll::Ready(Some(Err(e)))
                    }
                    Ok((rem, msgs)) => {
                        debug!("Collected {} eve messages", msgs.len());

                        *this.last_offset = rem.len();

                        let bytes_parsed = total_size - rem.len();
                        let mut to_keep = this.buf.split_off(bytes_parsed);
                        std::mem::swap(this.buf, &mut to_keep);
                        this.buf.reserve(BUFFER_SIZE - *this.last_offset);

                        let msgs: Result<Vec<_>, _> = msgs
                            .iter()
                            .map(|v| {
                                serde_json::from_slice::<T>(v.as_slice()).map_err(|e| {
                                    debug!(
                                        "Failed to decode: {}",
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

impl<T> std::convert::TryFrom<std::os::unix::net::UnixStream> for EveReader<T> {
    type Error = Error;
    fn try_from(v: std::os::unix::net::UnixStream) -> Result<Self, Error> {
        v.set_nonblocking(true)?;
        let s = smol::Async::new(v).map_err(Error::from)?;
        Ok(EveReader::from(s))
    }
}

impl<T> From<smol::Async<std::os::unix::net::UnixStream>> for EveReader<T> {
    fn from(v: smol::Async<std::os::unix::net::UnixStream>) -> Self {
        Self {
            inner: v,
            buf: Vec::with_capacity(BUFFER_SIZE),
            last_offset: 0,
            marker: std::marker::PhantomData,
            complete: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::EveMessage;
    use futures::{AsyncWriteExt, TryStreamExt};
    use std::convert::TryFrom;

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

        smol::Task::spawn(send_complete).detach();

        let alerts: Result<Vec<Vec<EveMessage>>, Error> =
            smol::run(EveReader::try_from(client).unwrap().try_collect());
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

        smol::Task::spawn(send_complete).detach();

        info!("Waiting for alerts");

        let alerts: Result<Vec<Vec<EveMessage>>, Error> =
            smol::run(EveReader::try_from(client).unwrap().try_collect());
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

        smol::Task::spawn(send_complete).detach();

        info!("Waiting for alerts");

        let alerts: Result<Vec<Vec<EveMessage>>, Error> =
            smol::run(EveReader::try_from(client).unwrap().try_collect());
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

        smol::Task::spawn(send_complete).detach();

        info!("Waiting for alerts");

        let alerts: Result<Vec<Vec<EveMessage>>, Error> =
            smol::run(EveReader::try_from(client).unwrap().try_collect());
        let alerts: Vec<_> = alerts.unwrap().into_iter().flat_map(|v| v).collect();

        assert_eq!(alerts.len(), 2);
    }
}
