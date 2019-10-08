use crate::errors::Error;
use crate::eve::json;

use futures::Stream;
use log::*;
use pin_project::pin_project;
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
    type Item = Result<Vec<Vec<u8>>, Error>;

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
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt as _;

    #[test]
    fn reads_eve() {
        let _ = env_logger::try_init();

        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        let (mut server, client) = tokio::net::UnixStream::pair().expect("Could not build pair");

        let send_complete = async move {
            let bytes = "{\"key1\":\"key with a paren set {}\",\"key2\":12345}{\"another\":\"part being sent\"}".as_bytes();

            server.write_all(bytes).await.expect("Failed to send");
            server.flush().await.expect("Failed to flush");

            info!("Send complete");
        };

        rt.spawn(send_complete);

        let fut_alerts = async {
            let alerts: Vec<_> = EveReader::from(client).collect().await;
            let alerts: Result<Vec<_>, Error> = alerts.into_iter().collect();
            let alerts: Vec<_> = alerts?.into_iter().flatten().collect();
            Ok(alerts) as Result<Vec<Vec<u8>>, Error>
        };

        info!("Waiting for alerts");

        let alerts = rt.block_on(fut_alerts).expect("Failed to receive alerts");
        let strings: Vec<_> = alerts
            .into_iter()
            .map(|v| String::from_utf8(v).expect("Not a valid string"))
            .collect();

        assert_eq!(
            strings,
            vec![
                "{\"key1\":\"key with a paren set {}\",\"key2\":12345}".to_string(),
                "{\"another\":\"part being sent\"}".to_string(),
            ]
        );
    }

    #[test]
    fn reads_partial_eve() {
        let _ = env_logger::try_init();

        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        let (mut server, client) = tokio::net::UnixStream::pair().expect("Could not build pair");

        let fut_alerts = async {
            let alerts: Vec<_> = EveReader::from(client).collect().await;
            let alerts: Result<Vec<_>, Error> = alerts.into_iter().collect();
            let alerts: Vec<_> = alerts?.into_iter().flatten().collect();
            Ok(alerts) as Result<Vec<Vec<u8>>, Error>
        };

        let send_complete = async move {
            let bytes = vec![
                "{\"key1\":\"key with a paren set {}\",\"key".as_bytes(),
                "2\":12345}{\"another\":".as_bytes(),
                "\"part being sent\"}".as_bytes(),
            ];
            for b in bytes {
                let f = server.write_all(b);

                f.await.expect("Failed to send");
            }

            info!("Send complete");
        };

        rt.block_on(send_complete);

        info!("Waiting for alerts");

        let alerts = rt.block_on(fut_alerts).expect("Failed to receive alerts");
        let strings: Vec<_> = alerts
            .into_iter()
            .map(|v| String::from_utf8(v).expect("Not a valid string"))
            .collect();

        assert_eq!(
            strings,
            vec![
                "{\"key1\":\"key with a paren set {}\",\"key2\":12345}".to_string(),
                "{\"another\":\"part being sent\"}".to_string(),
            ]
        );
    }

    #[test]
    fn reads_single_eve_event() {
        let _ = env_logger::try_init();

        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        let (mut server, client) = tokio::net::UnixStream::pair().expect("Could not build pair");

        let fut_alerts = async {
            let alerts: Vec<_> = EveReader::from(client).collect().await;
            let alerts: Result<Vec<_>, Error> = alerts.into_iter().collect();
            let alerts: Vec<_> = alerts?.into_iter().flatten().collect();
            Ok(alerts) as Result<Vec<Vec<u8>>, Error>
        };

        let send_complete = async move {
            let bytes = "{\"key1\":\"key without a return\"}".as_bytes();
            let f = server.write_all(bytes);

            f.await.expect("Failed to send");

            info!("Send complete");
        };

        rt.spawn(send_complete);

        info!("Waiting for alerts");

        let alerts = rt.block_on(fut_alerts).expect("Failed to receive alerts");
        let strings: Vec<_> = alerts
            .into_iter()
            .map(|v| String::from_utf8(v).expect("Not a valid string"))
            .collect();

        assert_eq!(
            strings,
            vec!["{\"key1\":\"key without a return\"}".to_string()]
        );
    }
}
