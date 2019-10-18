use crate::errors::Error;
use crate::eve::{json, Message};

use futures::Stream;
use log::*;
use pin_project::pin_project;
use std::convert::TryFrom;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_io::{AsyncBufRead, BufReader};
use tokio_net::uds::UnixStream;

const BUFFER_SIZE: usize = 1_000_000;

#[pin_project]
pub struct EveReader {
    #[pin]
    inner: tokio_io::BufReader<UnixStream>,
    buf: Vec<u8>,
}

impl Stream for EveReader {
    type Item = Result<Vec<Result<Message, Error>>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match futures::ready!(this.inner.as_mut().poll_fill_buf(cx)) {
            Err(e) => Poll::Ready(Some(Err(Error::Io(e)))),
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

                        let alerts: Vec<_> = alerts.iter().map(|v| Message::try_from(v.as_slice())).collect();

                        Poll::Ready(Some(Ok(alerts)))
                    }
                }
            }
        }
    }
}

impl From<UnixStream> for EveReader {
    fn from(v: UnixStream) -> Self {
        Self {
            inner: BufReader::new(v),
            buf: Vec::with_capacity(BUFFER_SIZE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::TryStreamExt;
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test]
    async fn reads_eve() {
        let _ = env_logger::try_init();

        let (mut server, client) = tokio::net::UnixStream::pair().expect("Could not build pair");

        let send_complete = async move {
            let bytes = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}},{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#.as_bytes();

            server.write_all(bytes).await.expect("Failed to send");
            server.flush().await.expect("Failed to flush");

            info!("Send complete");
        };

        tokio::spawn(send_complete);

        let alerts: Result<Vec<_>, Error> = EveReader::from(client).try_collect().await;
        let alerts: Result<Vec<_>, Error> = alerts.expect("Failed to get alerts").into_iter().flat_map(|v| v).collect();
        let alerts = alerts.expect("Failed to parse alerts");

        assert_eq!(alerts.len(), 2);
    }

    #[tokio::test]
    async fn reads_partial_eve() {
        let _ = env_logger::try_init();

        let (mut server, client) = tokio::net::UnixStream::pair().expect("Could not build pair");

        let send_complete = async move {
            let bytes = vec![
                r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-"#.as_bytes(),
                r#"18T10:48:14.622822-0700"}},{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip""#.as_bytes(),
                r#":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#.as_bytes(),
            ];
            for b in bytes {
                let f = server.write_all(b);

                f.await.expect("Failed to send");
            }

            info!("Send complete");
        };

        tokio::spawn(send_complete);

        info!("Waiting for alerts");

        let alerts: Result<Vec<_>, Error> = EveReader::from(client).try_collect().await;
        let alerts: Result<Vec<_>, Error> = alerts.expect("Failed to get alerts").into_iter().flat_map(|v| v).collect();
        let alerts = alerts.expect("Failed to parse alerts");

        assert_eq!(alerts.len(), 2);
    }

    #[tokio::test]
    async fn reads_single_eve_event() {
        let _ = env_logger::try_init();

        let (mut server, client) = tokio::net::UnixStream::pair().expect("Could not build pair");

        let send_complete = async move {
            let bytes = r#"{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}},{"timestamp":"2017-12-18T10:48:14.627130-0700","flow_id":2061665895874790,"pcap_cnt":7,"event_type":"alert","src_ip":"10.151.223.136","src_port":26475,"dest_ip":"203.0.113.99","dest_port":80,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":4113433437,"signature_id":600074,"rev":1,"signature":"ProtectWise Canary Test 1.3 - Not Malicious","category":"","severity":3},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":582,"bytes_toclient":302,"start":"2017-12-18T10:48:14.622822-0700"}}"#.as_bytes();
            let f = server.write_all(bytes);

            f.await.expect("Failed to send");

            info!("Send complete");
        };

        tokio::spawn(send_complete);

        info!("Waiting for alerts");

        let alerts: Result<Vec<_>, Error> = EveReader::from(client).try_collect().await;
        let alerts: Result<Vec<_>, Error> = alerts.expect("Failed to get alerts").into_iter().flat_map(|v| v).collect();
        let alerts = alerts.expect("Failed to parse alerts");

        assert_eq!(alerts.len(), 1);
    }
}
