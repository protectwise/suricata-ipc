use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "IO Error")]
    Io(#[fail(cause)] std::io::Error),
    #[fail(display = "Null pointer when dealing with ffi")]
    Ffi(#[fail(cause)] std::ffi::NulError),
    #[fail(display = "Utf8 conversion error")]
    Utf8(#[fail(cause)] std::string::FromUtf8Error),
    #[fail(display = "SystemTime error")]
    SystemTime(#[fail(cause)] std::time::SystemTimeError),
    #[fail(display = "ParseInt error")]
    ParseInt(#[fail(cause)] std::num::ParseIntError),
    #[fail(display = "Serde json conversion error")]
    SerdeJson(#[fail(cause)] serde_json::Error),
    #[fail(display = "IPC error")]
    PacketIpc(#[fail(cause)] packet_ipc::Error),
    #[fail(display = "No UDS connection formed")]
    NoUDSConnection,
    #[fail(display = "No rule found: {}:{}", gid, sid)]
    RuleNotFound { gid: u64, sid: u64 },
    #[fail(display = "Askama error")]
    Askama(#[fail(cause)] askama::Error),
    #[fail(display = "{}", msg)]
    Custom { msg: String },
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}
