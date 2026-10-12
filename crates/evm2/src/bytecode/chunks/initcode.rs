//! Frame-local initcode preparation and lazy chunk cache.

use super::{CODE_CHUNK_SIZE, CodeChunk, PreparedCodeChunk};
use crate::{
    bytecode::{Bytecode, JumpTable},
    interpreter::op,
};
use alloc::vec::Vec;
use alloy_primitives::Bytes;

/// Temporary initcode with one boundary scan and lazily prepared execution buffers.
#[derive(Debug)]
pub(crate) struct Initcode {
    bytes: Bytes,
    start_offsets: Vec<u8>,
    chunks: Vec<Option<CodeChunk>>,
}

impl Initcode {
    pub(crate) fn new(bytes: Bytes) -> Self {
        let count = bytes.len().div_ceil(CODE_CHUNK_SIZE);
        let mut start_offsets = Vec::with_capacity(count);
        let mut pc = 0;
        for start in (0..bytes.len()).step_by(CODE_CHUNK_SIZE) {
            while pc < start {
                let opcode = bytes[pc];
                pc += if (op::PUSH1..=op::PUSH32).contains(&opcode) {
                    usize::from(opcode - op::PUSH1) + 2
                } else {
                    1
                };
            }
            start_offsets.push((pc.min(bytes.len()) - start) as u8);
        }
        Self { bytes, start_offsets, chunks: alloc::vec![None; count] }
    }

    pub(crate) fn chunk(&mut self, index: u32) -> Option<CodeChunk> {
        let index = index as usize;
        let cached = self.chunks.get_mut(index)?;
        if let Some(chunk) = cached {
            return Some(chunk.clone());
        }
        if self.bytes.len() <= CODE_CHUNK_SIZE {
            let chunk = CodeChunk::new(self.bytes.clone());
            *cached = Some(chunk.clone());
            return Some(chunk);
        }
        let start = index * CODE_CHUNK_SIZE;
        let end = ((index + 1) * CODE_CHUNK_SIZE).min(self.bytes.len());
        let start_offset = usize::from(self.start_offsets[index]);
        // Original lookahead completes every possible immediate at the payload boundary.
        // It is never executed: dispatch switches chunks before the next opcode.
        let mut bytes = self.bytes[start..(end + 32).min(self.bytes.len())].to_vec();
        bytes.resize(end - start + 33, op::STOP);
        bytes.push(start_offset as u8);
        let mut jumps = JumpTable::new(bytes.len());
        let mut pc = start_offset;
        while pc < end - start {
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
        let padded = Bytecode::new_legacy(bytes.into());
        // SAFETY: The bytecode has ordinary immediate padding and a bounded jump table.
        let bytecode =
            unsafe { Bytecode::new_analyzed(padded.bytes().clone(), padded.len(), jumps) };
        let chunk = CodeChunk {
            bytecode,
            prepared: Some(PreparedCodeChunk {
                code_size: self.bytes.len() as u32,
                index: index as u32,
                payload_len: end - start,
            }),
        };
        *cached = Some(chunk.clone());
        Some(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::MAX_INITCODE_SIZE;

    #[test]
    fn initcode_prepares_only_requested_chunks() {
        let mut initcode = Initcode::new(alloc::vec![op::STOP; MAX_INITCODE_SIZE].into());
        assert!(initcode.chunks.iter().all(Option::is_none));
        initcode.chunk(0).unwrap();
        let last = initcode.chunks.len() - 1;
        initcode.chunk(last as u32).unwrap();
        assert_eq!(initcode.chunks.iter().filter(|chunk| chunk.is_some()).count(), 2);
        assert!(initcode.chunks[1..last].iter().all(Option::is_none));
        assert!(initcode.chunk(last as u32 + 1).is_none());
    }
}
