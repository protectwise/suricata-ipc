use rdkafka::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use smol::channel::{bounded, Receiver, Sender};
use smol::Task;
use std::time::Duration;
use suricata::{SCLogDebug, SCLogInfo, SCLogNotice};

use crate::Error;

/// Configuration for interacting with kafka
pub struct Config {
    pub in_flight_messages: usize,
    pub brokers: String,
    pub topic: String,
}

struct OutputHandle {
    task: Task<Result<(), Error>>,
}

impl OutputHandle {
    async fn new(
        receiver: Receiver<Vec<u8>>,
        config: Config,
    ) -> Result<OutputHandle, Error> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.brokers)
            .set("message.timeout.ms", "5000")
            .create()?;

        let task = smol::spawn(async move {
            while let Ok(msg) = receiver.recv().await {
                if let Err((e, _)) = producer
                    .send(
                        FutureRecord::to(&config.topic)
                            .key("")
                            .payload(msg.as_slice()),
                        Duration::from_secs(0),
                    )
                    .await {
                    SCLogNotice!("Failed to send message: {:?}", e);
                } else {
                    SCLogDebug!("Transmitted {}B", msg.len());
                }
            }
            Ok(())
        });
        Ok(Self {
            task: task,
        })
    }

    async fn close(self) -> Result<(), Error> {
        self.task.await
    }
}

pub struct Client {
    output_handle: OutputHandle,
    sender: Sender<Vec<u8>>,
}

impl Client {
    pub async fn new(config: Config) -> Result<Self, Error> {
        SCLogInfo!(
            "Connecting to {:?}",
            config.brokers,
        );

        let (sender, receiver) = bounded(config.in_flight_messages);

        Ok(Self {
            output_handle: OutputHandle::new(receiver, config).await?,
            sender: sender,
        })
    }

    pub async fn send(&self, msg: Vec<u8>) -> Result<(), Error> {
        self.sender.send(msg).await?;
        Ok(())
    }

    pub async fn close(self) -> Result<(), Error> {
        self.sender.close();
        let res = self.output_handle.close().await;
        res
    }
}
