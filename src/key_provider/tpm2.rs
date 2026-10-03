//! TPM2 unseal uses maintained ESAPI, a device-only TCTI and salted encryption.
use super::KeyProvider;
use crate::{
    Error, Result,
    memory::{LockedBytes, MemoryBudget},
};
use std::{str::FromStr, sync::Arc};
use tss_esapi::{
    Context,
    attributes::SessionAttributesBuilder,
    constants::SessionType,
    handles::{PersistentTpmHandle, SessionHandle, TpmHandle},
    interface_types::algorithm::HashingAlgorithm,
    structures::{Auth, Public, SymmetricDefinition},
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

pub struct Tpm2 {
    pub sealed_handle: u32,
    pub salt_handle: u32,
    /// SHA-256 TPM Names recorded during trusted provisioning, including hash ID.
    pub sealed_name: [u8; 34],
    pub salt_name: [u8; 34],
    pub auth: Box<dyn KeyProvider>,
}

impl KeyProvider for Tpm2 {
    fn load(&mut self, budget: &Arc<MemoryBudget>) -> Result<LockedBytes> {
        // Native TSS temporary allocations must have the same swap protection as
        // our owned buffers. This is permanent for the process, never munlockall.
        crate::memory::lock_address_space()?;

        let auth = self.auth.load(budget)?;

        let mut context = Context::new(TctiNameConf::Device(
            DeviceConfig::from_str("/dev/tpmrm0").map_err(|_| Error::Protection)?,
        ))
        .map_err(|_| Error::Protection)?;

        unseal(&mut context, self, &auth, budget)
    }

    fn name(&self) -> &'static str {
        "tpm2-device-salted"
    }
}

fn unseal(
    context: &mut Context,
    provider: &Tpm2,
    auth: &LockedBytes,
    budget: &Arc<MemoryBudget>,
) -> Result<LockedBytes> {
    let mut run = || -> tss_esapi::Result<LockedBytes> {
        let object = context.tr_from_tpm_public(TpmHandle::Persistent(
            PersistentTpmHandle::new(provider.sealed_handle)?,
        ))?;

        let key = context.tr_from_tpm_public(TpmHandle::Persistent(PersistentTpmHandle::new(
            provider.salt_handle,
        )?))?;

        let (public, name, _) = context.read_public(object.into())?;

        let (salt_public, salt_name, _) = context.read_public(key.into())?;

        let attributes = public.object_attributes();

        if !matches!(public, Public::KeyedHash { .. })
            || !attributes.fixed_tpm()
            || !attributes.fixed_parent()
            || !attributes.user_with_auth()
            || attributes.sign_encrypt()
            || attributes.decrypt()
            || attributes.restricted()
            || name.value() != provider.sealed_name
            || salt_name.value() != provider.salt_name
            || !matches!(salt_public, Public::Rsa { .. } | Public::Ecc { .. })
            || !salt_public.object_attributes().decrypt()
            || !salt_public.object_attributes().restricted()
        {
            return Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::InvalidParam,
            ));
        }

        context.tr_set_auth(object, Auth::try_from(auth.as_slice())?)?;

        let session = context
            .start_auth_session(
                Some(key.into()),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::InvalidParam,
            ))?;

        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();

        context.tr_sess_set_attributes(session, attributes, mask)?;

        let result = context.execute_with_session(Some(session), |c| c.unseal(object))?;

        if result.value().len() != 32 {
            return Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::InvalidParam,
            ));
        }

        // Rust-owned SensitiveData/Auth erase on Drop; native ESAPI heap copies
        // stay process-locked. Our public return value is uniquely page owned.
        let root = LockedBytes::from_slice(result.value(), budget).map_err(|_| {
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
        })?;

        context.flush_context(SessionHandle::from(session).into())?;

        Ok(root)
    };

    run().map_err(|_| Error::Protection)
}
