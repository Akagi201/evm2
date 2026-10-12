//! Shared encoded account extensions and borrowed views of their code metadata.

use crate::bytecode::{Bytecode, CodeChunkError, CodeMetadata, CodeMetadataRef};
use alloy_primitives::{Address, Bytes};
use core::ops::Deref;
use triomphe::ThinArc;

/// Encoded account data shared by snapshots in a one-pointer representation.
///
/// Empty means ordinary code. Byte 0 selects version 1 chunk commitments or a
/// version 2 delegation target. All nonempty payloads use a single allocation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountExtension(Option<ThinArc<(), u8>>);

impl AccountExtension {
    /// Creates an ordinary account extension without allocating.
    pub const fn new() -> Self {
        Self(None)
    }

    /// Creates `1 || last_chunk_size_be_u32 || chunk_hashes` in one shared allocation.
    pub fn chunked(metadata: CodeMetadata) -> Self {
        let size = metadata.last_chunk_size().to_be_bytes();
        let hashes = metadata.chunk_hashes();
        let bytes = (0..5 + 32 * hashes.len()).map(|offset| match offset {
            0 => 1,
            1..=4 => size[offset - 1],
            _ => hashes[(offset - 5) / 32][(offset - 5) % 32],
        });
        Self(Some(ThinArc::from_header_and_iter((), bytes)))
    }

    /// Creates `2 || target`. Account loading also checks its marker hash.
    pub fn delegated(target: Address) -> Self {
        let mut bytes = [2; 21];
        bytes[1..].copy_from_slice(target.as_slice());
        Self(Some(ThinArc::from_header_and_slice((), &bytes)))
    }

    /// Derives account metadata when explicitly installing complete bytecode.
    pub(crate) fn for_code(code: &Bytecode) -> Self {
        code.eip7702_address().map(Self::delegated).unwrap_or_default()
    }

    /// Returns whether this account uses ordinary code.
    pub const fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// Returns the first-byte extension type; zero denotes an empty extension.
    pub fn version(&self) -> u8 {
        self.first().copied().unwrap_or_default()
    }

    /// Borrows version 1 metadata directly from the encoded payload.
    pub fn code_metadata(&self) -> Option<CodeMetadataRef<'_>> {
        let [1, metadata @ ..] = self.as_ref() else { return None };
        Some(CodeMetadataRef::from_encoded(metadata).expect("validated extension metadata"))
    }

    /// Reads version 2's fixed-size delegation target.
    pub fn delegation_target(&self) -> Option<Address> {
        let [2, target @ ..] = self.as_ref() else { return None };
        Some(Address::from_slice(target))
    }

    /// Copies the already encoded extension into a byte buffer.
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self.as_ref())
    }

    /// Validates a complete extension, then copies it into a shared allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodeChunkError> {
        match bytes {
            [] => return Ok(Self::new()),
            [1, metadata @ ..] => {
                CodeMetadataRef::from_encoded(metadata)?;
            }
            [2, target @ ..] if target.len() == 20 => {
                if Address::from_slice(target).is_zero() {
                    return Err(CodeChunkError::InvalidMetadata);
                }
            }
            _ => return Err(CodeChunkError::InvalidMetadata),
        }
        Ok(Self(Some(ThinArc::from_header_and_slice((), bytes))))
    }
}

impl AsRef<[u8]> for AccountExtension {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().map_or(&[], |arc| &arc.slice)
    }
}

impl Deref for AccountExtension {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AccountExtension {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            alloy_primitives::hex::serialize(self.as_ref(), serializer)
        } else {
            serializer.serialize_bytes(self.as_ref())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AccountExtension {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Bytes::deserialize(deserializer)?;
        Self::decode(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::CODE_CHUNK_SIZE;
    use alloy_primitives::B256;

    #[test]
    fn chunked_encoding_stores_last_chunk_size() {
        for last_chunk_size in [1, CODE_CHUNK_SIZE as u32] {
            let metadata = CodeMetadata::new(last_chunk_size, alloc::vec![B256::ZERO; 3]).unwrap();
            let extension = AccountExtension::chunked(metadata);
            let mut expected = alloc::vec![1];
            expected.extend_from_slice(&last_chunk_size.to_be_bytes());
            expected.extend_from_slice(&[0; 96]);
            assert_eq!(extension.encode().as_ref(), expected);
            assert_eq!(AccountExtension::decode(&expected).unwrap(), extension);
            assert_eq!(
                extension.code_metadata().unwrap().code_size(),
                2 * CODE_CHUNK_SIZE as u32 + last_chunk_size
            );
        }
    }

    #[test]
    fn encoded_payload_is_one_pointer_and_shared_by_clones() {
        assert_eq!(size_of::<AccountExtension>(), size_of::<usize>());
        let empty = AccountExtension::new();
        assert!(empty.0.is_none());
        assert_eq!(empty.version(), 0);
        assert!(empty.as_ref().is_empty());
        for count in [2, crate::bytecode::MAX_CODE_CHUNKS] {
            let hashes = (0..count).map(|i| B256::repeat_byte(i as u8 + 1)).collect();
            let extension = AccountExtension::chunked(CodeMetadata::new(7, hashes).unwrap());
            let clone = extension.clone();
            assert_eq!(extension.as_ptr(), clone.as_ptr());
            assert_eq!(extension.version(), 1);
            assert_eq!(extension.len(), 5 + 32 * count);
            assert_eq!(extension.delegation_target(), None);
            let metadata = extension.code_metadata().unwrap();
            assert_eq!(metadata.chunk_count(), count);
            assert_eq!(metadata.last_chunk_size(), 7);
            assert_eq!(metadata.code_size() as usize, (count - 1) * CODE_CHUNK_SIZE + 7);
            for index in 0..count {
                let hash = B256::repeat_byte(index as u8 + 1);
                assert_eq!(metadata.chunk_hash(index as u32), Some(hash));
                assert_eq!(&extension[5 + 32 * index..5 + 32 * (index + 1)], hash.as_slice());
                assert_eq!(
                    metadata.chunk_len(index as u32),
                    Some(if index + 1 == count { 7 } else { CODE_CHUNK_SIZE })
                );
            }
            assert_eq!(metadata.chunk_hash(count as u32), None);
            assert_eq!(metadata.chunk_len(count as u32), None);
            assert_eq!(AccountExtension::decode(extension.as_ref()).unwrap(), extension);
        }
    }

    #[test]
    fn delegation_uses_type_byte_and_fixed_address_width() {
        let target = Address::repeat_byte(0x42);
        let extension = AccountExtension::delegated(target);
        assert_eq!(extension.version(), 2);
        assert_eq!(extension.len(), 21);
        assert_eq!(&extension[1..], target.as_slice());
        assert_eq!(extension.delegation_target(), Some(target));
        assert_eq!(extension.code_metadata(), None);
        assert_eq!(AccountExtension::decode(extension.as_ref()).unwrap(), extension);
    }

    #[test]
    fn decoding_rejects_invalid_types_sizes_and_counts() {
        for bytes in [
            &[0][..],
            &[3],
            &[1],
            &[2],
            &[2; 20],
            &[2; 22],
            &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(AccountExtension::decode(bytes), Err(CodeChunkError::InvalidMetadata));
        }
        for (size, hash_bytes) in [
            (0_u32, 64),
            (CODE_CHUNK_SIZE as u32 + 1, 64),
            (1, 0),
            (1, 32),
            (1, 63),
            (1, 65),
            (1, 41 * 32),
        ] {
            let mut bytes = alloc::vec![1];
            bytes.extend_from_slice(&size.to_be_bytes());
            bytes.resize(5 + hash_bytes, 0);
            assert_eq!(AccountExtension::decode(&bytes), Err(CodeChunkError::InvalidMetadata));
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_preserves_encoded_payloads() {
        for extension in [
            AccountExtension::new(),
            AccountExtension::delegated(Address::repeat_byte(0x42)),
            AccountExtension::chunked(
                CodeMetadata::new(7, alloc::vec![B256::repeat_byte(0x33); 2]).unwrap(),
            ),
        ] {
            let json = serde_json::to_string(&extension).unwrap();
            assert_eq!(json, serde_json::to_string(&extension.encode()).unwrap());
            assert_eq!(serde_json::from_str::<AccountExtension>(&json).unwrap(), extension);
            let binary = rmp_serde::to_vec(&extension).unwrap();
            assert_eq!(binary, rmp_serde::to_vec(&extension.encode()).unwrap());
            assert_eq!(rmp_serde::from_slice::<AccountExtension>(&binary).unwrap(), extension);
        }
    }
}
