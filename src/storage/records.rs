//! Canonical authenticated control records contain opaque IDs and ciphertext only.
use prost::Message;

pub const HEADER: i32 = 0;

pub const NAMESPACE: i32 = 1;

pub const SECRET: i32 = 2;

pub const VERSION: i32 = 3;

pub const RECIPIENT: i32 = 4;

pub const KEK: i32 = 5;

pub const NAME_INDEX: i32 = 6;

pub const FORMAT: u32 = 2;

#[derive(Clone, PartialEq, Message)]
pub struct NameRecord {
    #[prost(bytes = "vec", tag = "1")]
    pub secret: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Header {
    #[prost(uint32, tag = "1")]
    pub format: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub active_kek: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub rotating_from: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub audit_sequence: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub audit_tip: Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub ciphertext_bytes: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub rotation_cursor: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NamespaceRecord {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    #[prost(bool, tag = "2")]
    pub live: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct SecretRecord {
    #[prost(uint64, tag = "1")]
    pub active: u64,
    #[prost(uint64, tag = "2")]
    pub latest: u64,
    #[prost(bool, tag = "3")]
    pub enabled: bool,
    #[prost(bytes = "vec", tag = "4")]
    pub name_index: Vec<u8>,
    #[prost(bool, tag = "5")]
    pub deleted: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct RecipientRecord {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct KeyRecord {
    #[prost(message, optional, tag = "1")]
    pub wrapped: Option<crate::crypto::Blob>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AuditEvent {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(uint64, tag = "2")]
    pub timestamp_ns: u64,
    #[prost(enumeration = "EventKind", tag = "3")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub namespace: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub object: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub uid: u32,
    #[prost(uint32, tag = "7")]
    pub pid: u32,
    #[prost(bytes = "vec", tag = "8")]
    pub previous: Vec<u8>,
    #[prost(message, repeated, tag = "9")]
    pub changes: Vec<StateChange>,
}

/// Authenticated state transitions contain only opaque record IDs and MACs.
#[derive(Clone, PartialEq, Message)]
pub struct StateChange {
    #[prost(int32, tag = "1")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub tag: Vec<u8>, // empty means a durable tombstone/removal
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum EventKind {
    Startup = 0,
    NamespaceCreate = 1,
    NamespaceDelete = 2,
    SecretCreate = 3,
    SecretVersion = 4,
    SecretActivate = 5,
    SecretDisable = 6,
    SecretDelete = 7,
    CapabilityIssue = 8,
    CapabilityRedeem = 9,
    CapabilityReject = 10,
    CapabilityRevoke = 11,
    RecipientRevoke = 12,
    NamespaceRevoke = 13,
    KeyLoad = 14,
    RotationBegin = 15,
    RotationBatch = 16,
    RotationComplete = 17,
    AdminReject = 18,
    Recovery = 19,
}

impl AuditEvent {
    pub fn new(kind: EventKind, namespace: &[u8], object: &[u8], uid: u32, pid: u32) -> Self {
        Self {
            kind: kind as i32,
            namespace: namespace.into(),
            object: object.into(),
            uid,
            pid,
            ..Self::default()
        }
    }
}

pub fn secret_key(namespace: &[u8; 16], secret: &[u8; 16]) -> Vec<u8> {
    [namespace.as_slice(), secret.as_slice()].concat()
}

pub fn version_key(namespace: &[u8; 16], secret: &[u8; 16], version: u64) -> Vec<u8> {
    [
        namespace.as_slice(),
        secret.as_slice(),
        version.to_be_bytes().as_slice(),
    ]
    .concat()
}
