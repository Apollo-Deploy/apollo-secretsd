//! Administration is accepted exclusively on the privileged socket.
use prost::{Message, Oneof};

#[derive(Clone, PartialEq, Message)]
pub struct AdminRequest {
    #[prost(
        oneof = "admin_request::Action",
        tags = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"
    )]
    pub action: Option<admin_request::Action>,
}

pub mod admin_request {

    use super::*;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum Action {
        #[prost(message, tag = "1")]
        Status(Empty),
        #[prost(message, tag = "2")]
        NamespaceCreate(Empty),
        #[prost(message, tag = "3")]
        NamespaceInspect(Identity),
        #[prost(message, tag = "4")]
        NamespaceDelete(Identity),
        #[prost(message, tag = "5")]
        SecretCreate(SecretInput),
        #[prost(message, tag = "6")]
        SecretPut(SecretInput),
        #[prost(message, tag = "7")]
        SecretMetadata(SecretRef),
        #[prost(message, tag = "8")]
        SecretList(ListSecrets),
        #[prost(message, tag = "9")]
        SecretActivate(SecretRef),
        #[prost(message, tag = "10")]
        SecretDisable(SecretRef),
        #[prost(message, tag = "11")]
        SecretDelete(SecretRef),
        #[prost(message, tag = "12")]
        GrantIssue(IssueGrant),
        #[prost(message, tag = "13")]
        Revoke(Revoke),
        #[prost(message, tag = "14")]
        KeyStatus(Empty),
        #[prost(message, tag = "15")]
        KeyRotate(Empty),
        #[prost(message, tag = "16")]
        Audit(AuditQuery),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

#[derive(Clone, PartialEq, Message)]
pub struct Identity {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListSecrets {
    #[prost(bytes = "vec", tag = "1")]
    pub namespace: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub after: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct SecretRef {
    #[prost(bytes = "vec", tag = "1")]
    pub namespace: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub secret: Vec<u8>,
    /// Zero resolves CURRENT at issuance, never at redemption.
    #[prost(uint64, tag = "3")]
    pub version: u64,
}

#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
pub struct SecretInput {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<SecretRef>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(uint64, tag = "3")]
    pub length: u64,
    // Exact secret bytes are supplied as one sealed SCM_RIGHTS FD.
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.name);
    }
}

impl std::fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretInput([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct IssueGrant {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<SecretRef>,
    #[prost(bytes = "vec", tag = "2")]
    pub recipient: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub generation: u64,
    #[prost(uint32, tag = "4")]
    pub uid: u32,
    #[prost(uint32, tag = "5")]
    pub gid: u32,
    #[prost(uint32, tag = "6")]
    pub pid: u32,
    #[prost(uint32, tag = "7")]
    pub ttl_ms: u32,
    #[prost(uint32, tag = "8")]
    pub max_uses: u32,
    #[prost(string, tag = "9")]
    pub cgroup: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Revoke {
    #[prost(enumeration = "RevocationKind", tag = "1")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub next_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum RevocationKind {
    Capability = 0,
    Recipient = 1,
    Namespace = 2,
}

#[derive(Clone, PartialEq, Message)]
pub struct AuditQuery {
    #[prost(bool, tag = "1")]
    pub verify: bool,
    #[prost(uint64, tag = "2")]
    pub after: u64,
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct Response {
    #[prost(enumeration = "ErrorCode", tag = "1")]
    pub error: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub version: u64,
    #[prost(uint64, tag = "4")]
    pub generation: u64,
    #[prost(string, tag = "5")]
    pub daemon_version: String,
    #[prost(uint32, tag = "6")]
    pub minimum_protocol: u32,
    #[prost(uint32, tag = "7")]
    pub maximum_protocol: u32,
    #[prost(string, repeated, tag = "8")]
    pub capabilities: Vec<String>,
    #[prost(message, repeated, tag = "9")]
    pub entries: Vec<Entry>,
    #[prost(uint64, tag = "10")]
    pub fd_length: u64,
}

#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
pub struct Entry {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub version: u64,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(bool, tag = "4")]
    pub enabled: bool,
}

impl Drop for Entry {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.name);
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entry([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    Ok = 0,
    Invalid = 1,
    Denied = 2,
    NotFound = 3,
    Limit = 4,
    Unavailable = 5,
    Integrity = 6,
    Conflict = 7,
}
