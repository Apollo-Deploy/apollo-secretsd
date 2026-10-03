//! Distinct, fixed-size opaque identities prevent authorization type confusion.
macro_rules! id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(pub [u8; 16]);

        impl TryFrom<&[u8]> for $name {
            type Error = crate::ProtocolError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                let bytes: [u8; 16] = value
                    .try_into()
                    .map_err(|_| crate::ProtocolError::Identity)?;

                if bytes == [0; 16] {
                    return Err(crate::ProtocolError::Identity);
                }

                Ok(Self(bytes))
            }
        }
    };
}

id!(NamespaceId);

id!(SecretId);

id!(RecipientId);

id!(CapabilityId);

id!(OperationId);

id!(PrincipalId);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NamespaceGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RecipientGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SecretVersion(pub u64);
