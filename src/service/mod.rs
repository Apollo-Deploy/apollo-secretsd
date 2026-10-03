//! Serialized authorization/state/audit boundary, shared by a tiny bounded pool.
mod dispatch;
mod grants;
mod namespaces;
mod secrets;

use crate::{Result, capability::Grants, config::Limits, storage::Store};
pub use dispatch::Reply;

pub struct Service {
    pub(crate) store: Store,
    pub(crate) grants: Grants,
    pub(crate) limits: Limits,
    pub(crate) provider_name: &'static str,
}

impl Service {
    pub fn new(store: Store, limits: Limits) -> Result<Self> {
        limits.validate()?;

        Ok(Self {
            grants: Grants::new(&limits),
            store,
            limits,
            provider_name: "embedded-root",
        })
    }

    /// Record the trusted startup provider for operational diagnostics.
    pub fn with_provider(
        store: Store,
        limits: Limits,
        provider: &dyn crate::key_provider::KeyProvider,
    ) -> Result<Self> {
        let mut service = Self::new(store, limits)?;

        service.provider_name = provider.name();

        Ok(service)
    }

    pub fn maintenance(&mut self) -> Result<()> {
        self.grants.expire();

        if self.store.rotation_pending() {
            self.store.rotate_batch(1)?;
        }

        Ok(())
    }
}
