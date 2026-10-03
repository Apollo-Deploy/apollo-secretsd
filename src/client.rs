//! Standalone public protocol client. Delivered bytes remain caller-owned FD data.
use crate::{
    Error, Result, crypto,
    delivery::transport,
    memory::{LockedBytes, MemoryBudget},
};
use prost::Message;
use rustix::{
    event::{PollFd, PollFlags, Timespec},
    fd::OwnedFd,
    net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType},
};
use secretsd_protocol::*;
use std::{path::Path, sync::Arc};

pub struct Client {
    socket: OwnedFd,
    budget: Arc<MemoryBudget>,
}

impl Client {
    pub fn connect(path: &Path, server_uid: u32, budget: Arc<MemoryBudget>) -> Result<Self> {
        let socket = net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;

        // Bound blocking Unix connect/send/receive, including a full listen backlog.
        for operation in [net::sockopt::Timeout::Send, net::sockopt::Timeout::Recv] {
            net::sockopt::set_socket_timeout(
                &socket,
                operation,
                Some(std::time::Duration::from_secs(5)),
            )?;
        }

        net::sockopt::set_socket_passcred(&socket, true)?;

        net::connect(&socket, &SocketAddrUnix::new(path)?)?;

        if net::sockopt::socket_peercred(&socket)?.uid.as_raw() != server_uid {
            return Err(Error::Denied);
        }

        Ok(Self { socket, budget })
    }

    pub fn admin(
        self,
        request: AdminRequest,
        fd: Option<&OwnedFd>,
    ) -> Result<(Response, Option<OwnedFd>)> {
        let mut payload = LockedBytes::new(request.encoded_len().max(1), &self.budget)?;

        request
            .encode(&mut &mut payload.as_mut_slice()[..request.encoded_len()])
            .map_err(|_| Error::Invalid)?;

        self.exchange(
            ADMIN_REQUEST,
            ADMIN_RESPONSE,
            &payload.as_slice()[..request.encoded_len()],
            fd,
        )
    }

    pub fn redeem(self, token: &[u8; 32]) -> Result<OwnedFd> {
        let (response, fd) = self.exchange(REDEEM_REQUEST, DELIVERY_RESPONSE, token, None)?;

        let fd = fd.ok_or(Error::Integrity)?;

        if response.fd_length == 0 || response.fd_length > 4 * 1024 * 1024 {
            return Err(Error::Integrity);
        }

        crate::delivery::validate(&fd, response.fd_length as usize)?;

        Ok(fd)
    }

    fn exchange(
        self,
        kind: u16,
        response_kind: u16,
        payload: &[u8],
        fd: Option<&OwnedFd>,
    ) -> Result<(Response, Option<OwnedFd>)> {
        let id = OperationId(crypto::random_id()?);

        let mut frame = LockedBytes::new(HEADER_LEN + payload.len(), &self.budget)?;

        let length = encode_frame_into(id, kind, payload, frame.as_mut_slice())?;

        let sent = transport::send(&self.socket, &frame.as_slice()[..length], fd);

        drop(frame);

        sent?;

        let mut polls = [PollFd::new(&self.socket, PollFlags::IN)];

        if rustix::event::poll(
            &mut polls,
            Some(&Timespec {
                tv_sec: 5,
                tv_nsec: 0,
            }),
        )? != 1
        {
            return Err(Error::Limit);
        }

        let mut buffer = LockedBytes::new(MAX_FRAME, &self.budget)?;

        let received = transport::receive(&self.socket, buffer.as_mut_slice())?;

        let credentials = received.credentials.as_ref().ok_or(Error::Denied)?;

        let peer = net::sockopt::socket_peercred(&self.socket)?;

        if peer.pid != credentials.pid || peer.uid != credentials.uid || peer.gid != credentials.gid
        {
            return Err(Error::Denied);
        }

        let frame = Frame::decode(&buffer.as_slice()[..received.bytes])?;

        if frame.request_id != id || frame.message_type != response_kind {
            return Err(Error::Integrity);
        }

        let response = decode_canonical::<Response>(frame.payload)?;

        if response.error != ErrorCode::Ok as i32 {
            return Err(
                match ErrorCode::try_from(response.error).map_err(|_| Error::Integrity)? {
                    ErrorCode::Denied => Error::Denied,
                    ErrorCode::NotFound => Error::NotFound,
                    ErrorCode::Conflict => Error::Conflict,
                    ErrorCode::Limit => Error::Limit,
                    ErrorCode::Integrity => Error::Integrity,
                    _ => Error::Invalid,
                },
            );
        }

        if received.fd.is_some() != (response.fd_length > 0) {
            return Err(Error::Integrity);
        }

        Ok((response, received.fd))
    }
}
