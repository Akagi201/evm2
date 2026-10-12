//! Prepared TIP-1143 bytecode chunks and deployment commitments.

use super::{Bytecode, JumpTable};
use crate::interpreter::{instructions::encode_rjump_offset, op};
use alloc::vec::Vec;
use alloy_primitives::{B256, Bytes};
use thiserror::Error;

/// Original bytes in a full runtime chunk.
pub const CODE_CHUNK_SIZE: usize = 24 * 1024 - 36;
/// Maximum unchanged legacy record and prepared execution buffer size.
pub const LEGACY_CODE_CHUNK_SIZE: usize = 24 * 1024;
/// Maximum number of runtime chunks.
pub const MAX_CODE_CHUNKS: usize = 40;
/// Draft runtime byte limit.
pub const MAX_CODE_SIZE: usize = CODE_CHUNK_SIZE * MAX_CODE_CHUNKS;
/// Draft initcode byte limit (2 MiB), independent of the runtime chunk count.
pub const MAX_INITCODE_SIZE: usize = 2 * 1024 * 1024;
/// Draft cold chunk tariff, pending production calibration.
pub const COLD_CODE_CHUNK_GAS: u64 = 28_680;
/// Draft warm chunk tariff.
pub const WARM_CODE_CHUNK_GAS: u64 = 1_000;

/// Account code loaded as either a complete legacy record or a prepared runtime chunk.
#[derive(Clone, Debug)]
pub enum CodeChunk {
    /// Complete legacy account code, without chunk context or a generated trailer.
    Legacy(Bytecode),
    /// One slice of a larger runtime, with its logical size and index.
    Prepared(PreparedCodeChunk),
}

impl PartialEq for CodeChunk {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Legacy(code), Self::Legacy(other)) => {
                code == other && code.kind() == other.kind()
            }
            (Self::Prepared(chunk), Self::Prepared(other)) => chunk == other,
            _ => false,
        }
    }
}

impl Eq for CodeChunk {}

impl Default for CodeChunk {
    fn default() -> Self {
        Self::from_bytecode(&Bytecode::default())
    }
}

impl From<Bytecode> for CodeChunk {
    fn from(code: Bytecode) -> Self {
        Self::Legacy(code)
    }
}

impl CodeChunk {
    /// Wraps ordinary code without interpreting a delegation-shaped prefix.
    pub fn new(bytes: Bytes) -> Self {
        Bytecode::new_legacy(bytes).into()
    }

    /// Retains an existing bytecode allocation and its shared analysis.
    pub fn from_bytecode(code: &Bytecode) -> Self {
        code.clone().into()
    }

    /// Returns the single stored execution buffer and its lazy jump analysis.
    pub fn bytecode(&self) -> Bytecode {
        self.as_bytecode().clone()
    }

    /// Stored bytes, including continued immediates, the generated tail and start-offset byte.
    /// Ordinary interpreter safety padding is excluded.
    pub fn bytes(&self) -> &[u8] {
        self.as_bytecode().original_byte_slice()
    }

    /// Number of logical code positions represented by this chunk, excluding its tail.
    pub fn payload_len(&self) -> usize {
        match self {
            Self::Legacy(code) => code.len(),
            Self::Prepared(chunk) => chunk.payload_len(),
        }
    }

    /// Number of leading immediate bytes belonging to the previous chunk's instruction.
    /// The count is the last stored byte; ordinary legacy records have no trailer.
    pub fn start_offset(&self) -> usize {
        if self.prepared().is_some() { usize::from(*self.bytes().last().unwrap()) } else { 0 }
    }

    /// Restores an already modified chunk authenticated by the provider at ingestion.
    /// The payload keeps its original bytes; the final byte identifies leading immediate data.
    pub fn from_prepared(bytes: Bytes, code_size: u32, index: u32) -> Result<Self, CodeChunkError> {
        let start = (index as usize)
            .checked_mul(CODE_CHUNK_SIZE)
            .ok_or(CodeChunkError::InvalidPreparation)?;
        let size = code_size as usize;
        if !(CODE_CHUNK_SIZE + 1..=MAX_CODE_SIZE).contains(&size) || start >= size {
            return Err(CodeChunkError::InvalidPreparation);
        }
        let payload_len = (size - start).min(CODE_CHUNK_SIZE);
        if bytes.len() <= payload_len || bytes.len() > LEGACY_CODE_CHUNK_SIZE {
            return Err(CodeChunkError::InvalidPreparation);
        }
        let start_offset = usize::from(*bytes.last().unwrap());
        if start_offset > payload_len.min(32) || (index == 0 && start_offset != 0) {
            return Err(CodeChunkError::InvalidPreparation);
        }
        let mut instruction_end = start_offset;
        while instruction_end < payload_len {
            instruction_end += instruction_len(bytes[instruction_end]);
        }
        let tail_offset = payload_len + 32;
        let continuation_len = instruction_end - payload_len;
        if bytes.get(instruction_end..tail_offset)
            != Some(padding_suffix(continuation_len).as_slice())
        {
            return Err(CodeChunkError::InvalidPreparation);
        }
        let next_chunk = (start + instruction_end < size).then_some(index + 1);
        let tail: &[u8] = if next_chunk.is_some() { &[op::RJUMP, 0x5a, 0x38] } else { &[op::STOP] };
        if bytes.get(tail_offset..bytes.len() - 1) != Some(tail) {
            return Err(CodeChunkError::InvalidPreparation);
        }
        // The prefix belongs to the preceding instruction, even if it contains JUMPDEST.
        // Preserve the existing PUSH-only jump analysis after the first real opcode.
        let mut jumps = JumpTable::new(bytes.len());
        let mut pc = start_offset;
        while pc < payload_len {
            let opcode = bytes[pc];
            if opcode == op::JUMPDEST {
                jumps.as_mut_slice()[pc / 8] |= 1 << (pc % 8);
            }
            pc += if (op::PUSH1..=op::PUSH32).contains(&opcode) {
                usize::from(opcode - op::PUSH1) + 2
            } else {
                1
            };
        }
        // Only generated padding JUMPDESTs are valid physical destinations beyond the payload.
        for pc in instruction_end..tail_offset {
            if bytes[pc] == op::JUMPDEST {
                jumps.as_mut_slice()[pc / 8] |= 1 << (pc % 8);
            }
        }
        let padded = Bytecode::new_legacy(bytes);
        // SAFETY: new_legacy supplies ordinary safety padding for all immediate reads.
        // The map has one bit per stored byte and excludes prefix data and generated tails.
        let bytecode =
            unsafe { Bytecode::new_analyzed(padded.bytes().clone(), padded.len(), jumps) };
        Ok(Self::Prepared(PreparedCodeChunk { bytecode, code_size, index }))
    }

    /// Prepared runtime buffer and its logical context, absent for legacy records.
    pub const fn prepared(&self) -> Option<&PreparedCodeChunk> {
        match self {
            Self::Legacy(_) => None,
            Self::Prepared(chunk) => Some(chunk),
        }
    }

    /// Checks the loaded buffer's logical size and index against the account.
    pub fn validate_context(&self, code_size: u32, index: u32) -> Result<(), CodeChunkError> {
        if self.prepared().is_some_and(|p| p.code_size == code_size && p.index == index) {
            Ok(())
        } else {
            Err(CodeChunkError::InvalidPreparation)
        }
    }

    /// Dynamic jumps may enter only JUMPDESTs in the logical payload.
    pub fn is_valid_jumpdest(&self, local_pc: usize) -> bool {
        local_pc < self.payload_len()
            && self.as_bytecode().legacy_jump_table().is_some_and(|map| map.is_valid(local_pc))
    }

    /// Borrows the owned bytecode and its immutable execution analysis.
    pub const fn as_bytecode(&self) -> &Bytecode {
        match self {
            Self::Legacy(code) => code,
            Self::Prepared(chunk) => &chunk.bytecode,
        }
    }

    /// Logical chunk index; ordinary unchunked code starts at zero.
    pub const fn index(&self) -> u32 {
        match self {
            Self::Legacy(_) => 0,
            Self::Prepared(chunk) => chunk.index,
        }
    }

    /// Complete logical code length, excluding prepared padding and tails.
    pub fn code_size(&self) -> usize {
        match self {
            Self::Legacy(code) => code.len(),
            Self::Prepared(chunk) => chunk.code_size as usize,
        }
    }
}

/// Validated commitments present only for multi-chunk code.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "MetadataFields"))]
pub struct CodeMetadata {
    last_chunk_size: u32,
    chunk_hashes: Vec<B256>,
}

impl CodeMetadata {
    /// Validates the last chunk size and ordered hash count.
    /// Payload authentication belongs to ingestion.
    pub fn new(last_chunk_size: u32, chunk_hashes: Vec<B256>) -> Result<Self, CodeChunkError> {
        if !(1..=CODE_CHUNK_SIZE as u32).contains(&last_chunk_size)
            || !(2..=MAX_CODE_CHUNKS).contains(&chunk_hashes.len())
        {
            return Err(CodeChunkError::InvalidMetadata);
        }
        Ok(Self { last_chunk_size, chunk_hashes })
    }

    /// Committed original code length.
    pub const fn code_size(&self) -> u32 {
        (self.chunk_hashes.len() as u32 - 1) * CODE_CHUNK_SIZE as u32 + self.last_chunk_size
    }

    /// Ordered commitments to complete stored chunk buffers, including the start-offset byte.
    pub fn chunk_hashes(&self) -> &[B256] {
        &self.chunk_hashes
    }

    /// Exact payload length for an in-range index, without provider access.
    pub fn chunk_len(&self, index: u32) -> Option<usize> {
        let index = usize::try_from(index).ok()?;
        (index < self.chunk_hashes.len()).then(|| {
            if index == self.chunk_hashes.len() - 1 {
                self.last_chunk_size as usize
            } else {
                CODE_CHUNK_SIZE
            }
        })
    }

    /// Committed original payload length of the last chunk.
    pub const fn last_chunk_size(&self) -> u32 {
        self.last_chunk_size
    }
}

/// Deployment or metadata validation failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CodeChunkError {
    /// Runtime exceeds the draft capacity.
    #[error("runtime exceeds the TIP-1143 code size limit")]
    CodeTooLarge,
    /// Size and commitments do not describe multi-chunk code.
    #[error("invalid multi-chunk code metadata")]
    InvalidMetadata,
    /// Provider preparation violates the bounded instruction layout.
    #[error("invalid chunk preparation")]
    InvalidPreparation,
    /// A PUSH immediate crosses a payload boundary or the original code end.
    #[error("PUSH immediate at byte {pc} crosses a code chunk boundary")]
    PushCrossesBoundary {
        /// Global PUSH opcode offset.
        pc: usize,
    },
    /// The last original byte of a non-final chunk is not a decoded STOP.
    #[error("code chunk {index} does not end with STOP")]
    ChunkWithoutStop {
        /// Original payload index.
        index: usize,
    },
}

/// Checks the capacity of submitted original bytes; PUSH continuations are prepared separately.
pub const fn validate_code(code: &[u8]) -> Result<(), CodeChunkError> {
    if code.len() > MAX_CODE_SIZE {
        return Err(CodeChunkError::CodeTooLarge);
    }

    Ok(())
}

/// Validates creation output and commits to the stored, modified chunk buffers.
pub fn code_metadata(code: &[u8]) -> Result<Option<CodeMetadata>, CodeChunkError> {
    validate_code(code)?;
    if code.len() <= CODE_CHUNK_SIZE {
        return Ok(None);
    }
    let last_chunk_size = ((code.len() - 1) % CODE_CHUNK_SIZE + 1) as u32;
    let code = Bytes::copy_from_slice(code);
    let hashes = (0..code.len().div_ceil(CODE_CHUNK_SIZE))
        .map(|index| {
            code_chunk(&code, index as u32)
                .expect("validated chunk index")
                .as_bytecode()
                .hash_slow()
        })
        .collect();
    CodeMetadata::new(last_chunk_size, hashes).map(Some)
}

/// Prepares one chunk at creation or ingestion, without retaining its original slice.
pub fn code_chunk(code: &Bytes, index: u32) -> Option<CodeChunk> {
    let start = usize::try_from(index).ok()?.checked_mul(CODE_CHUNK_SIZE)?;
    if start >= code.len() {
        return None;
    }
    if code.len() <= CODE_CHUNK_SIZE {
        return Some(CodeChunk::new(code.clone()));
    }
    let end = start.checked_add(CODE_CHUNK_SIZE)?.min(code.len());
    let mut pc = 0;
    while pc < start {
        pc += instruction_len(code[pc]);
    }
    let leading = pc.min(end).saturating_sub(start);
    pc = pc.min(end);
    while pc < end {
        pc += instruction_len(code[pc]);
    }
    let mut bytes = code[start..pc.min(code.len())].to_vec();
    bytes.resize(pc - start, 0);
    bytes.extend_from_slice(&padding_suffix(pc - end));
    if pc < code.len() {
        // The fixed padding and RJUMP width place the successor's logical start 35 bytes back.
        // The transfer handler then advances over that chunk's leading immediate data.
        bytes.push(op::RJUMP);
        bytes.extend_from_slice(&encode_rjump_offset(-35).unwrap());
    } else {
        bytes.push(op::STOP);
    }
    bytes.push(leading as u8);
    CodeChunk::from_prepared(bytes.into(), code.len().try_into().ok()?, index).ok()
}

/// Checked aggregate incremental tariff for one operation.
pub const fn code_chunk_gas(cold: u64, warm: u64) -> Option<u64> {
    match (cold.checked_mul(COLD_CODE_CHUNK_GAS), warm.checked_mul(WARM_CODE_CHUNK_GAS)) {
        (Some(cold), Some(warm)) => cold.checked_add(warm),
        _ => None,
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct MetadataFields {
    last_chunk_size: u32,
    chunk_hashes: Vec<B256>,
}

#[cfg(feature = "serde")]
impl TryFrom<MetadataFields> for CodeMetadata {
    type Error = CodeChunkError;

    fn try_from(fields: MetadataFields) -> Result<Self, Self::Error> {
        Self::new(fields.last_chunk_size, fields.chunk_hashes)
    }
}

/// Validated executable runtime buffer and the context needed to load adjacent chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCodeChunk {
    bytecode: Bytecode,
    code_size: u32,
    index: u32,
}

impl PreparedCodeChunk {
    /// Complete logical code size.
    pub const fn code_size(&self) -> u32 {
        self.code_size
    }

    /// Position in the account's ordered chunk list.
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Logical bytes in this chunk, excluding continuation bytes, padding and the tail.
    pub const fn payload_len(&self) -> usize {
        let remaining = self.code_size as usize - self.index as usize * CODE_CHUNK_SIZE;
        if remaining < CODE_CHUNK_SIZE { remaining } else { CODE_CHUNK_SIZE }
    }

    /// Local position of the generated RJUMP or STOP.
    pub const fn tail_offset(&self) -> usize {
        self.payload_len() + 32
    }
}

fn instruction_len(opcode: u8) -> usize {
    if (0x60..=0x7f).contains(&opcode) {
        usize::from(opcode - 0x5f) + 1
    } else if matches!(opcode, op::RJUMP | op::RJUMPI) {
        3
    } else if (0xe6..=0xe8).contains(&opcode) {
        2
    } else {
        1
    }
}

/// Fill unused padding with a checked local jump, or up to three JUMPDESTs.
fn padding_suffix(continuation_len: usize) -> Vec<u8> {
    let remaining = 32 - continuation_len;
    let mut padding = alloc::vec![op::JUMPDEST; remaining];
    if remaining >= 4 {
        padding.fill(op::STOP);
        padding[0] = op::RJUMP;
        padding[1..3].copy_from_slice(&encode_rjump_offset((remaining - 4) as isize).unwrap());
        padding[remaining - 1] = op::JUMPDEST;
    }
    padding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_last_chunk_size() {
        for size in
            [CODE_CHUNK_SIZE + 1, 2 * CODE_CHUNK_SIZE, 2 * CODE_CHUNK_SIZE + 1, MAX_CODE_SIZE]
        {
            let metadata = code_metadata(&alloc::vec![op::STOP; size]).unwrap().unwrap();
            let count = size.div_ceil(CODE_CHUNK_SIZE);
            let last_chunk_size = size - (count - 1) * CODE_CHUNK_SIZE;
            assert_eq!(metadata.code_size() as usize, size);
            assert_eq!(metadata.chunk_hashes().len(), count);
            assert_eq!(metadata.last_chunk_size() as usize, last_chunk_size);
            for index in 0..count - 1 {
                assert_eq!(metadata.chunk_len(index as u32), Some(CODE_CHUNK_SIZE));
            }
            assert_eq!(metadata.chunk_len(count as u32 - 1), Some(last_chunk_size));
            assert_eq!(metadata.chunk_len(count as u32), None);
            assert_eq!(metadata.chunk_len(u32::MAX), None);
        }
    }

    #[test]
    fn metadata_rejects_invalid_size_and_count() {
        for (last_chunk_size, count) in [
            (0, 2),
            (CODE_CHUNK_SIZE as u32 + 1, 2),
            (u32::MAX, 2),
            (1, 0),
            (1, 1),
            (1, MAX_CODE_CHUNKS + 1),
        ] {
            assert_eq!(
                CodeMetadata::new(last_chunk_size, alloc::vec![B256::ZERO; count]),
                Err(CodeChunkError::InvalidMetadata)
            );
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn metadata_serde_last_chunk_size() {
        let metadata = CodeMetadata::new(7, alloc::vec![B256::ZERO; 3]).unwrap();
        let json = serde_json::json!({
            "last_chunk_size": 7,
            "chunk_hashes": [B256::ZERO, B256::ZERO, B256::ZERO],
        });
        assert_eq!(serde_json::to_value(&metadata).unwrap(), json);
        assert_eq!(serde_json::from_value::<CodeMetadata>(json).unwrap(), metadata);
        for last_chunk_size in [0, CODE_CHUNK_SIZE as u32 + 1] {
            let json = serde_json::json!({
                "last_chunk_size": last_chunk_size,
                "chunk_hashes": [B256::ZERO, B256::ZERO],
            });
            assert!(serde_json::from_value::<CodeMetadata>(json).is_err());
        }
    }
}
