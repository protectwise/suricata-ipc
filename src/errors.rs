use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("IO Error: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("Null pointer when dealing with ffi: {0:?}")]
    Ffi(#[from] std::ffi::NulError),
    #[error("Utf8 conversion error: {0:?}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("SystemTime error: {0:?}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("ParseInt error: {0:?}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Serde json conversion error: {0:?}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("IPC error")]
    PacketIpc(#[from] packet_ipc::Error),
    #[error("No UDS connection formed")]
    NoUDSConnection,
    #[error("No rule found: {}:{}", gid, sid)]
    RuleNotFound { gid: u64, sid: u64 },
    #[error("Askama error: {0:?}")]
    Askama(#[from] askama::Error),
    #[error("Missing server ID: {0}")]
    MissingServer(usize),
    #[error("{0}", msg)]
    Custom { msg: String },
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}
