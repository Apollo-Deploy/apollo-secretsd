//! Issue exact grants, fence generations, consume atomically before audited delivery.
use super::Service;
use crate::{
    Error, Result,
    auth::Process,
    capability::{Grant, Peer},
    crypto::{self, Scope},
    delivery::SealedSecret,
    memory::LockedBytes,
    storage::*,
};
use secretsd_protocol::*;
use std::time::{Duration, Instant};

impl Service {
    pub fn issue(
        &mut self,
        request: IssueGrant,
        admin: Peer,
    ) -> Result<(CapabilityId, SealedSecret)> {
        let reference = request.scope.ok_or(Error::Invalid)?;

        let namespace = NamespaceId::try_from(reference.namespace.as_slice())?;

        let secret = SecretId::try_from(reference.secret.as_slice())?;

        let scope = self.resolve(namespace, secret, reference.version)?;

        let recipient = RecipientId::try_from(request.recipient.as_slice())?;

        let generation = RecipientGeneration(request.generation);

        if generation.0 == 0 {
            return Err(Error::Invalid);
        }

        let ttl = if request.ttl_ms == 0 {
            30000.min(self.limits.grant_ttl_ms)
        } else {
            request.ttl_ms
        };

        let uses = if request.max_uses == 0 {
            1
        } else {
            request.max_uses
        };

        if ttl > self.limits.grant_ttl_ms || uses > self.limits.grant_uses {
            return Err(Error::Limit);
        }

        let process = Process::capture(request.pid)?;

        if process.peer.uid != request.uid || process.peer.gid != request.gid {
            return Err(Error::Denied);
        }

        if !request.cgroup.is_empty() && request.cgroup != process.cgroup {
            return Err(Error::Denied);
        }

        let existing = self.recipient_generation(recipient);

        let mut changes = Vec::new();

        match existing {
            Ok(current) if generation < current => return Err(Error::Denied),
            Ok(current) if generation == current => {}
            Ok(_) | Err(Error::NotFound) => {
                if matches!(existing, Err(Error::NotFound))
                    && self.store.count(RECIPIENT, None) >= self.limits.recipients
                {
                    return Err(Error::Limit);
                }

                changes.push(Change::put(
                    RECIPIENT,
                    &recipient.0,
                    &RecipientRecord {
                        generation: generation.0,
                    },
                ));
            }
            Err(e) => return Err(e),
        }

        let id = CapabilityId(crypto::random_id()?);

        let token = LockedBytes::random(32, &self.store.keys().budget)?;

        let digest = self.store.keys().grant_digest(token.key()?)?;

        let sealed = SealedSecret::new(&token)?;

        let grant = Grant {
            id,
            namespace,
            namespace_generation: NamespaceGeneration(self.namespace(namespace)?.generation),
            secret,
            version: scope.version,
            recipient,
            generation,
            peer: process.peer,
            cgroup: if request.cgroup.is_empty() {
                None
            } else {
                Some(request.cgroup)
            },
            expires: Instant::now() + Duration::from_millis(u64::from(ttl)),
            remaining: uses,
            process,
        };

        self.grants.insert(digest, grant)?;

        if let Err(error) = self.store.commit(
            AuditEvent::new(
                EventKind::CapabilityIssue,
                &namespace.0,
                &id.0,
                admin.uid,
                admin.pid,
            ),
            &changes,
            None,
        ) {
            self.grants.revoke_capability(id);

            return Err(error);
        }

        Ok((id, sealed))
    }

    pub fn redeem(&mut self, token: &[u8; 32], process: &Process) -> Result<SealedSecret> {
        let peer = process.peer;

        let store = &self.store;

        let authorized = self.grants.consume(
            store.keys(),
            token,
            peer,
            |id| {
                let ns: NamespaceRecord = store.record(NAMESPACE, &id.0)?;

                if !ns.live {
                    return Err(Error::Denied);
                }

                Ok(NamespaceGeneration(ns.generation))
            },
            |id| {
                let recipient: RecipientRecord = store.record(RECIPIENT, &id.0)?;

                Ok(RecipientGeneration(recipient.generation))
            },
            Some(&process.cgroup),
        );

        let grant = match authorized {
            Ok(grant) => grant,
            Err(error) => {
                self.store.commit(
                    AuditEvent::new(EventKind::CapabilityReject, &[], &[], peer.uid, peer.pid),
                    &[],
                    None,
                )?;

                return Err(error);
            }
        };

        self.store.commit(
            AuditEvent::new(
                EventKind::CapabilityRedeem,
                &grant.namespace.0,
                &grant.id.0,
                peer.uid,
                peer.pid,
            ),
            &[],
            None,
        )?;

        self.resolve(grant.namespace, grant.secret, grant.version.0)?;

        let plaintext = self.secret_material(
            Scope {
                namespace: grant.namespace,
                secret: grant.secret,
                version: grant.version,
            },
            false,
        )?;

        if !process.alive()? || !grant.process.alive()? {
            return Err(Error::Denied);
        }

        SealedSecret::new(&plaintext)
    }

    pub fn revoke(&mut self, request: Revoke, peer: Peer) -> Result<()> {
        let kind = RevocationKind::try_from(request.kind).map_err(|_| Error::Invalid)?;

        match kind {
            RevocationKind::Capability => {
                let id = CapabilityId::try_from(request.id.as_slice())?;

                self.store.commit(
                    AuditEvent::new(EventKind::CapabilityRevoke, &[], &id.0, peer.uid, peer.pid),
                    &[],
                    None,
                )?;

                self.grants.revoke_capability(id);
            }
            RevocationKind::Recipient => {
                let id = RecipientId::try_from(request.id.as_slice())?;

                let current = self.recipient_generation(id)?;

                let next = current.0.checked_add(1).ok_or(Error::Limit)?;

                if request.next_generation < next {
                    return Err(Error::Invalid);
                }

                self.store.commit(
                    AuditEvent::new(EventKind::RecipientRevoke, &[], &id.0, peer.uid, peer.pid),
                    &[Change::put(
                        RECIPIENT,
                        &id.0,
                        &RecipientRecord {
                            generation: request.next_generation,
                        },
                    )],
                    None,
                )?;

                self.grants.revoke_recipient(id);
            }
            RevocationKind::Namespace => {
                let id = NamespaceId::try_from(request.id.as_slice())?;

                self.namespace(id)?;

                self.store.commit(
                    AuditEvent::new(EventKind::NamespaceRevoke, &id.0, &[], peer.uid, peer.pid),
                    &[],
                    None,
                )?;

                self.grants.revoke_namespace(id);
            }
        }

        Ok(())
    }
}
