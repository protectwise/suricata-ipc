use crate::errors::Error;
use crate::eve::json;

use futures::io::BufReader;
use futures::{AsyncBufRead, Stream};
use log::*;
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

const BUFFER_SIZE: usize = 1_000_000;

type AsyncStream = smol::Async<std::os::unix::net::UnixStream>;

#[pin_project]
pub struct EveReader<T> {
    #[pin]
    inner: BufReader<AsyncStream>,
    buf: Vec<u8>,
    marker: std::marker::PhantomData<T>,
}

impl<T> Stream for EveReader<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    type Item = Result<Vec<T>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match futures::ready!(this.inner.as_mut().poll_fill_buf(cx)) {
            Err(e) => Poll::Ready(Some(Err(Error::from(e)))),
            Ok(available) => {
                let bytes_read = available.len();

                trace!("Read {}B", bytes_read);

                if bytes_read == 0 {
                    return Poll::Ready(None);
                }

                this.buf.extend_from_slice(available);
                this.inner.as_mut().consume(bytes_read);

                trace!("Collecting alerts from {} bytes", this.buf.len());
                match json::JsonParser::parse(this.buf.as_ref()) {
                    Err(e) => Poll::Ready(Some(Err(e))),
                    Ok((rem, alerts)) => {
                        debug!("Collected {} alerts", alerts.len());
                        let unread_position = this.buf.len() - rem.len();
                        let mut to_keep = this.buf.split_off(unread_position);
                        std::mem::swap(this.buf, &mut to_keep);

                        debug!("Alerts available");

                        let alerts: Result<Vec<_>, _> = alerts
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

                        Poll::Ready(Some(alerts))
                    }
                }
            }
        }
    }
}

impl<T> std::convert::TryFrom<std::os::unix::net::UnixStream> for EveReader<T> {
    type Error = Error;
    fn try_from(v: std::os::unix::net::UnixStream) -> Result<Self, Error> {
        Ok(Self {
            inner: BufReader::new(smol::Async::new(v).map_err(Error::from)?),
            buf: Vec::with_capacity(BUFFER_SIZE),
            marker: std::marker::PhantomData,
        })
    }
}

impl<T> From<smol::Async<std::os::unix::net::UnixStream>> for EveReader<T> {
    fn from(v: smol::Async<std::os::unix::net::UnixStream>) -> Self {
        Self {
            inner: BufReader::new(v),
            buf: Vec::with_capacity(BUFFER_SIZE),
            marker: std::marker::PhantomData,
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
}
