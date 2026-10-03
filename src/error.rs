//! Public errors deliberately contain no payload, token, key, name or DB content.
use secretsd_protocol::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid request or configuration")]
    Invalid,
    #[error("authorization denied")]
    Denied,
    #[error("record not found")]
    NotFound,
    #[error("resource limit reached")]
    Limit,
    #[error("state integrity failure")]
    Integrity,
    #[error("conflicting operation")]
    Conflict,
    #[error("required protection unavailable")]
    Protection,
    #[error("I/O unavailable")]
    Io(#[from] std::io::Error),
    #[error("system operation unavailable (errno {})", .0.raw_os_error())]
    Sys(#[from] rustix::io::Errno),
    #[error("transaction unavailable")]
    Database(#[from] rusqlite::Error),
    #[error("protocol rejected")]
    Protocol(#[from] secretsd_protocol::ProtocolError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Invalid | Self::Protocol(_) => ErrorCode::Invalid,
            Self::Denied => ErrorCode::Denied,
            Self::NotFound => ErrorCode::NotFound,
            Self::Limit => ErrorCode::Limit,
            Self::Integrity => ErrorCode::Integrity,
            Self::Conflict => ErrorCode::Conflict,
            _ => ErrorCode::Unavailable,
        }
    }
}
