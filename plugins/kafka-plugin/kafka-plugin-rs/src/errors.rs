use thiserror::Error as ThisError;

/// Errors that can occur while sending data via UDS
#[derive(Debug, ThisError)]
pub enum Error {
    /// Kafka Error
    #[error("Kafka: {0:?}")]
    Kafka(#[from] rdkafka::error::KafkaError),
    /// IO Error
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    /// Unable to send message via channel
    #[error("Send message: {0:?}")]
    SendMessageError(#[from] smol::channel::SendError<std::vec::Vec<u8>>),
}
