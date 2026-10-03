//! Safe rustix `SCM_RIGHTS` handling; malformed/truncated packets close every FD.
use crate::{Error, Result};
use rustix::{
    fd::{AsFd, OwnedFd},
    net::{
        self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, UCred,
    },
};
use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
};

pub struct Received {
    pub bytes: usize,
    pub fd: Option<OwnedFd>,
    pub credentials: Option<UCred>,
}

pub fn receive(socket: impl AsFd, buffer: &mut [u8]) -> Result<Received> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];

    let mut ancillary = RecvAncillaryBuffer::new(&mut space);

    let msg = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(buffer)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
    )?;

    let mut fd = None;

    let mut credentials = None;

    let mut invalid = msg
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC);

    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => {
                for received in rights {
                    if fd.is_some() {
                        invalid = true;
                    } else {
                        fd = Some(received);
                    }
                }
            }
            RecvAncillaryMessage::ScmCredentials(cred) => {
                if credentials.is_some() {
                    invalid = true;
                } else {
                    credentials = Some(cred);
                }
            }
            _ => invalid = true,
        }
    }

    if invalid || msg.bytes > buffer.len() {
        return Err(Error::Invalid);
    }

    Ok(Received {
        bytes: msg.bytes,
        fd,
        credentials,
    })
}

pub fn send(socket: impl AsFd, bytes: &[u8], fd: Option<&OwnedFd>) -> Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];

    let mut ancillary = SendAncillaryBuffer::new(&mut space);

    let rights = fd.map(|f| [f.as_fd()]);

    if let Some(rights) = &rights
        && !ancillary.push(SendAncillaryMessage::ScmRights(rights))
    {
        return Err(Error::Limit);
    }

    let sent = net::sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
    )?;

    if sent != bytes.len() {
        return Err(Error::Invalid);
    }

    Ok(())
}
