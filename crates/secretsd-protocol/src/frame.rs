//! Fixed header, bounded canonical protobuf, and a token-only delivery frame.
use prost::Message;
use zeroize::Zeroize;

pub const MAGIC: [u8; 4] = *b"ASD1";

pub const PROTOCOL_MIN: u16 = 1;

pub const PROTOCOL_MAX: u16 = 1;

pub const HEADER_LEN: usize = 28;

pub const MAX_FRAME: usize = 65536;

pub const ADMIN_REQUEST: u16 = 1;

pub const ADMIN_RESPONSE: u16 = 2;

pub const REDEEM_REQUEST: u16 = 3;

pub const DELIVERY_RESPONSE: u16 = 4;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid or unsupported frame")]
    Frame,
    #[error("invalid opaque identity")]
    Identity,
    #[error("invalid or noncanonical message")]
    Message,
}

pub struct Frame<'a> {
    pub request_id: crate::OperationId,
    pub message_type: u16,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        if !(HEADER_LEN..=MAX_FRAME).contains(&bytes.len()) || bytes[..4] != MAGIC {
            return Err(ProtocolError::Frame);
        }

        let version = u16::from_be_bytes([bytes[4], bytes[5]]);

        let message_type = u16::from_be_bytes([bytes[6], bytes[7]]);

        let size = u32::from_be_bytes(bytes[24..28].try_into().map_err(|_| ProtocolError::Frame)?);

        if version != PROTOCOL_MAX || usize::try_from(size).ok() != Some(bytes.len() - HEADER_LEN) {
            return Err(ProtocolError::Frame);
        }

        Ok(Self {
            request_id: crate::OperationId::try_from(&bytes[8..24])?,
            message_type,
            payload: &bytes[HEADER_LEN..],
        })
    }
}

pub fn encode_frame(
    id: crate::OperationId,
    kind: u16,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let mut out = vec![0; HEADER_LEN + payload.len().min(MAX_FRAME)];

    let length = encode_frame_into(id, kind, payload, &mut out)?;

    out.truncate(length);

    Ok(out)
}

/// The caller chooses protected storage when a payload contains a capability.
pub fn encode_frame_into(
    id: crate::OperationId,
    kind: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, ProtocolError> {
    if payload.len() > MAX_FRAME - HEADER_LEN {
        return Err(ProtocolError::Frame);
    }

    let length = HEADER_LEN + payload.len();

    if out.len() < length {
        return Err(ProtocolError::Frame);
    }

    out[..4].copy_from_slice(&MAGIC);

    out[4..6].copy_from_slice(&PROTOCOL_MAX.to_be_bytes());

    out[6..8].copy_from_slice(&kind.to_be_bytes());

    out[8..24].copy_from_slice(&id.0);

    out[24..28].copy_from_slice(&(payload.len() as u32).to_be_bytes());

    out[HEADER_LEN..length].copy_from_slice(payload);

    Ok(length)
}

/// Reject unknown fields, duplicate fields, and ambiguous encodings at the boundary.
pub fn decode_canonical<T: Message + Default>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_FRAME - HEADER_LEN {
        return Err(ProtocolError::Message);
    }

    let value = T::decode(bytes).map_err(|_| ProtocolError::Message)?;

    let mut encoded = value.encode_to_vec();

    let canonical = encoded == bytes;

    encoded.zeroize();

    if !canonical {
        return Err(ProtocolError::Message);
    }

    Ok(value)
}

/// No namespace, secret, recipient, version, UID or PID can be submitted here.
pub struct Redeem<'a> {
    token: &'a [u8; 32],
}

impl<'a> Redeem<'a> {
    pub fn decode(frame: &Frame<'a>) -> Result<Self, ProtocolError> {
        if frame.message_type != REDEEM_REQUEST {
            return Err(ProtocolError::Frame);
        }

        Ok(Self {
            token: frame
                .payload
                .try_into()
                .map_err(|_| ProtocolError::Message)?,
        })
    }

    pub fn token(&self) -> &[u8; 32] {
        self.token
    }
}

impl core::fmt::Debug for Redeem<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Redeem([REDACTED])")
    }
}
