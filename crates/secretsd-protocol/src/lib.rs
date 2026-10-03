//! Public, standalone protocol. One canonical message per `AF_UNIX` SEQPACKET.
//! Secret values and issued capabilities travel in sealed FDs, never protobuf.
mod admin;
mod frame;
mod ids;

pub use admin::*;
pub use frame::*;
pub use ids::*;
