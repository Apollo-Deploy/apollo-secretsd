//! Typed admin dispatch; callers authenticate admin credentials before entering.
use super::Service;
use crate::{
    Error, Result,
    capability::Peer,
    crypto::Scope,
    delivery::{self, SealedSecret},
    storage::*,
};
use rustix::fd::OwnedFd;
use secretsd_protocol::{admin_request::Action, *};

pub struct Reply {
    pub response: Response,
    pub secret: Option<SealedSecret>,
}

impl Service {
    pub fn admin(
        &mut self,
        request: AdminRequest,
        fd: Option<OwnedFd>,
        peer: Peer,
    ) -> Result<Reply> {
        let action = request.action.ok_or(Error::Invalid)?;

        let create = matches!(action, Action::SecretCreate(_));

        if fd.is_some() && !matches!(action, Action::SecretCreate(_) | Action::SecretPut(_)) {
            return Err(Error::Invalid);
        }

        let mut response = Response::default();

        let mut secret = None;

        match action {
            Action::Status(_) => {
                response.daemon_version = env!("CARGO_PKG_VERSION").into();

                response.minimum_protocol = u32::from(PROTOCOL_MIN);

                response.maximum_protocol = u32::from(PROTOCOL_MAX);

                response.capabilities = vec![
                    "sealed-memfd".into(),
                    "pidfd".into(),
                    "xchacha20poly1305".into(),
                    "memory-only-grants".into(),
                ];

                response
                    .capabilities
                    .push(format!("key-provider:{}", self.provider_name));

                response
                    .capabilities
                    .push(if self.store.keys().root.is_secret_memory() {
                        "root-memfd-secret".into()
                    } else {
                        "root-mlock-dontdump".into()
                    });
            }
            Action::NamespaceCreate(_) => response.id = self.namespace_create(peer)?.0.to_vec(),
            Action::NamespaceInspect(id) => {
                let id = NamespaceId::try_from(id.id.as_slice())?;

                let ns = self.namespace(id)?;

                response.id = id.0.to_vec();

                response.generation = ns.generation;
            }
            Action::NamespaceDelete(id) => {
                self.namespace_delete(NamespaceId::try_from(id.id.as_slice())?, peer)?;
            }
            Action::SecretCreate(input) | Action::SecretPut(input) => {
                let reference = input.scope.as_ref().ok_or(Error::Invalid)?;

                let namespace = NamespaceId::try_from(reference.namespace.as_slice())?;

                let id = if reference.secret.is_empty() {
                    None
                } else {
                    Some(SecretId::try_from(reference.secret.as_slice())?)
                };

                if create == id.is_some() || reference.version != 0 {
                    return Err(Error::Invalid);
                }

                let length = usize::try_from(input.length).map_err(|_| Error::Limit)?;

                let plaintext = delivery::import(
                    fd.ok_or(Error::Invalid)?,
                    length,
                    self.limits.secret_bytes,
                    &self.store.keys().budget,
                )?;

                let (id, version) =
                    self.secret_put(namespace, id, &input.name, &plaintext, peer)?;

                response.id = id.0.to_vec();

                response.version = version.0;
            }
            Action::SecretMetadata(reference) => {
                let scope = parse_scope(reference)?;

                response
                    .entries
                    .push(self.secret_metadata(scope.namespace, scope.secret)?);
            }
            Action::SecretList(query) => {
                let after = if query.after.is_empty() {
                    None
                } else {
                    Some(SecretId::try_from(query.after.as_slice())?)
                };

                let limit = if query.limit == 0 {
                    128
                } else {
                    query.limit as usize
                };

                response.entries = self.secret_list(
                    NamespaceId::try_from(query.namespace.as_slice())?,
                    after,
                    limit,
                )?;
            }
            Action::SecretActivate(reference) => {
                self.secret_change(parse_scope(reference)?, EventKind::SecretActivate, peer)?;
            }
            Action::SecretDisable(reference) => {
                self.secret_change(parse_scope(reference)?, EventKind::SecretDisable, peer)?;
            }
            Action::SecretDelete(reference) => {
                self.secret_change(parse_scope(reference)?, EventKind::SecretDelete, peer)?;
            }
            Action::GrantIssue(request) => {
                let (id, fd) = self.issue(request, peer)?;

                response.id = id.0.to_vec();

                response.fd_length = 32;

                secret = Some(fd);
            }
            Action::Revoke(request) => self.revoke(request, peer)?,
            Action::KeyStatus(_) => {
                response.id = self.store.active_kek()?.0.to_vec();

                response.capabilities.push(
                    if self.store.rotation_pending() {
                        "rotation-pending"
                    } else {
                        "rotation-complete"
                    }
                    .into(),
                );
            }
            Action::KeyRotate(_) => {
                response.id = self.store.begin_rotation(peer.uid, peer.pid)?.to_vec();
            }
            Action::Audit(query) => {
                if query.verify {
                    self.store.verify_all()?;
                }

                let limit = if query.limit == 0 {
                    32
                } else {
                    query.limit as usize
                };

                for event in self.store.audit_tail(query.after, limit)? {
                    response.entries.push(Entry {
                        id: event.object,
                        version: event.sequence,
                        name: format!(
                            "{:?}",
                            EventKind::try_from(event.kind).map_err(|_| Error::Integrity)?
                        ),
                        enabled: true,
                    });
                }
            }
        }

        Ok(Reply { response, secret })
    }
}

fn parse_scope(reference: SecretRef) -> Result<Scope> {
    Ok(Scope {
        namespace: NamespaceId::try_from(reference.namespace.as_slice())?,
        secret: SecretId::try_from(reference.secret.as_slice())?,
        version: SecretVersion(reference.version),
    })
}
