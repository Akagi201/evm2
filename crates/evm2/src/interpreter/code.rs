//! Frame-local execution cursor over shared code chunks.
//!
//! Account chunks are loaded and warmed by the host. Initcode prepares its own chunks here.
//! This module owns the active allocation, its borrowed view, and every chunk switch.

use super::{BytecodeRef, CodeSource, Gas, Host, InterpreterState, Pc, Result, Word};
use crate::{
    EvmTypesHost,
    bytecode::{CODE_CHUNK_SIZE, COLD_CODE_CHUNK_GAS, CodeChunk, Initcode, WARM_CODE_CHUNK_GAS},
    trustme,
    utils::word_to_usize_saturated,
};
use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::Address;

/// Code ownership and execution position for one interpreter frame.
#[derive(Debug)]
pub(super) struct InterpreterCode {
    active: CodeChunk,
    source: Source,
    // Borrows immutable allocations owned by `active`. Accessors shorten the erased lifetime;
    // activation clears this view before replacing the owning chunk.
    view: Option<BytecodeRef<'static>>,
    pub(super) pc: *const u8,
}

/// Loading policy and frame-local preparation, independent of account access warmth.
#[derive(Debug)]
enum Source {
    Direct,
    Account,
    Initcode(Box<Initcode>),
}

impl Default for InterpreterCode {
    fn default() -> Self {
        Self::new(&CodeSource::default())
    }
}

impl InterpreterCode {
    pub(super) fn new(code: &CodeSource) -> Self {
        let (active, source) = match code {
            CodeSource::Direct(code) => (CodeChunk::from_bytecode(code), Source::Direct),
            CodeSource::Account(chunk) => (chunk.clone(), Source::Account),
            CodeSource::Initcode(bytes) if bytes.len() <= CODE_CHUNK_SIZE => {
                (CodeChunk::new(bytes.clone()), Source::Direct)
            }
            CodeSource::Initcode(bytes) => {
                let mut initcode = Initcode::new(bytes.clone());
                let active = initcode.chunk(0).unwrap_or_default();
                (active, Source::Initcode(Box::new(initcode)))
            }
        };
        let pc = active.as_bytecode().bytes_slice().as_ptr();
        Self { active, source, pc, view: None }
    }

    pub(super) const fn active(&self) -> &CodeChunk {
        &self.active
    }

    pub(super) const fn is_account(&self) -> bool {
        matches!(self.source, Source::Account)
    }

    pub(super) const fn is_chunked(&self) -> bool {
        !matches!(self.source, Source::Direct)
    }

    pub(super) fn view(&self) -> BytecodeRef<'_> {
        self.view.unwrap_or_else(|| BytecodeRef::new(self.active.as_bytecode()))
    }

    /// Only called during instruction execution, after `prepare` initialized the view.
    pub(super) const fn prepared_view(&self) -> BytecodeRef<'_> {
        // SAFETY: `prepare` and every chunk switch initialize the view before execution.
        unsafe { self.view.unwrap_unchecked() }
    }

    pub(super) fn prepare(&mut self) {
        if self.view.is_none() {
            // SAFETY: The chunk owns immutable heap allocations, so moving this structure
            // leaves the view valid. No accessor exposes the erased lifetime.
            let bytecode = unsafe { trustme::decouple_lt(self.active.as_bytecode()) };
            self.view = Some(BytecodeRef::new(bytecode));
        }
    }

    pub(super) fn activate(&mut self, chunk: CodeChunk) {
        self.view = None;
        self.active = chunk;
        self.pc = self.active.as_bytecode().bytes_slice().as_ptr();
        self.prepare();
    }

    pub(super) fn pc(&self) -> usize {
        self.global_pc(Pc::new(self.pc))
    }

    pub(super) fn set_pc(&mut self, pc: usize) {
        let local = pc
            .checked_sub(self.active.index() as usize * CODE_CHUNK_SIZE)
            .expect("PC is outside the active chunk");
        if self.active.prepared().is_some() {
            assert!(local < self.active.payload_len(), "PC is outside the logical payload");
        }
        let bytes = self.active.as_bytecode().bytes_slice();
        assert!(local < bytes.len());
        // SAFETY: The local offset is inside the active allocation.
        self.pc = unsafe { bytes.as_ptr().add(local) };
    }

    pub(super) fn global_pc(&self, pc: Pc) -> usize {
        // SAFETY: Every execution PC points into the active chunk.
        let local =
            unsafe { pc.as_ptr().offset_from(self.active.as_bytecode().bytes_slice().as_ptr()) };
        local as usize + self.active.index() as usize * CODE_CHUNK_SIZE
    }

    pub(super) fn is_internal(&self, pc: Pc) -> bool {
        self.is_account()
            && self.active.prepared().is_some()
            && self.view().pc_offset(pc) >= self.active.payload_len()
    }

    pub(super) fn is_generated_tail(&self, pc: Pc) -> bool {
        self.is_account()
            && self.active.prepared().is_some_and(|p| self.view().pc_offset(pc) == p.tail_offset())
    }

    /// Account sources return `None` so the caller can reserve gas before host I/O.
    pub(super) fn initcode_chunk(&mut self, index: u32) -> Option<CodeChunk> {
        match &mut self.source {
            Source::Initcode(code) => Some(code.chunk(index).expect("validated initcode index")),
            Source::Direct | Source::Account => None,
        }
    }

    /// Advances initcode across a payload boundary without executing synthetic instructions.
    #[inline]
    pub(super) fn advance_initcode_pc(&mut self, pc: &mut Pc) {
        if !matches!(self.source, Source::Initcode(_)) || self.active.prepared().is_none() {
            return;
        }
        let local = self.prepared_view().pc_offset(*pc);
        if local < self.active.payload_len() {
            return;
        }
        let next_pc = self.global_pc(*pc);
        if next_pc >= self.active.code_size() {
            return;
        }
        let index = (next_pc / CODE_CHUNK_SIZE) as u32;
        let chunk = self.initcode_chunk(index).expect("initcode source");
        self.activate(chunk);
        // SAFETY: The next instruction is inside the newly activated logical chunk.
        unsafe { pc.set_unchecked(self.prepared_view(), next_pc % CODE_CHUNK_SIZE) };
    }
}

impl<T: EvmTypesHost> InterpreterState<'_, '_, T> {
    /// Whether this frame executes through chunked bytecode buffers.
    pub const fn is_chunked_code(&self) -> bool {
        self.0.code.is_chunked()
    }

    /// Complete logical code size, excluding execution padding.
    pub fn code_size(&self) -> usize {
        self.0.code.active().code_size()
    }

    /// Active payload index in the logical contract.
    pub const fn code_chunk_index(&self) -> u32 {
        self.0.code.active().index()
    }

    /// Original global offset of the active instruction.
    pub fn global_pc(&self, pc: Pc) -> usize {
        self.0.code.global_pc(pc)
    }

    /// Authenticates the generated tail by its recorded offset, never by opcode alone.
    pub(crate) fn is_generated_tail(&self, pc: Pc) -> bool {
        self.0.code.is_generated_tail(pc)
    }

    /// Validates against the complete logical jump map before choosing an execution view.
    pub(crate) const fn active_chunk(&self) -> &CodeChunk {
        self.0.code.active()
    }

    /// Tariff based only on logical warmth, before any payload fetch.
    pub(crate) fn chunk_tariff(&mut self, address: &Address, index: u32) -> u64 {
        if self.host().code_chunk_is_warm(address, index) {
            WARM_CODE_CHUNK_GAS
        } else {
            COLD_CODE_CHUNK_GAS
        }
    }

    /// Loads a required payload after the caller has reserved gas.
    pub(crate) fn required_code_chunk(
        &mut self,
        address: &Address,
        index: u32,
    ) -> Result<CodeChunk> {
        self.host().load_code_chunk(address, index).map_err(|error| self.fail(error))?.ok_or_else(
            || {
                self.fail(crate::DatabaseError::new(
                    MissingRuntimeChunk { address: *address, index },
                    true,
                ))
            },
        )
    }

    /// Replaces the owner before rebuilding its borrowed view. Callers reset their PC next.
    pub(crate) fn activate_code_chunk(&mut self, chunk: CodeChunk) {
        self.0.code.activate(chunk);
    }

    /// Loads an execution chunk from frame-local initcode or the account host.
    pub(crate) fn execution_code_chunk(&mut self, gas: &mut Gas, index: u32) -> Result<CodeChunk> {
        if let Some(chunk) = self.0.code.initcode_chunk(index) {
            return Ok(chunk);
        }
        let address = self.message().code_address;
        gas.spend(self.chunk_tariff(&address, index))?;
        self.required_code_chunk(&address, index)
    }

    /// Reserves the complete known range tariff before its first payload read.
    pub(crate) fn load_code_range(
        &mut self,
        gas: &mut Gas,
        code_owner: Address,
        source: Word,
        len: usize,
        size: usize,
        multi: bool,
    ) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let source = word_to_usize_saturated(source);
        if source >= size {
            return Ok(Vec::new());
        }
        let end = source.saturating_add(len).min(size);
        let (first, last) = if multi {
            ((source / CODE_CHUNK_SIZE) as u32, ((end - 1) / CODE_CHUNK_SIZE) as u32)
        } else {
            (0, 0)
        };
        let mut cost = 0;
        for index in first..=last {
            cost += self.chunk_tariff(&code_owner, index);
        }
        gas.spend(cost)?;
        let mut bytes = Vec::new();
        for index in first..=last {
            let chunk = self.required_code_chunk(&code_owner, index)?;
            let base = if multi { index as usize * CODE_CHUNK_SIZE } else { 0 };
            let from = source.saturating_sub(base).min(chunk.payload_len());
            let to = end.saturating_sub(base).min(chunk.payload_len());
            if from < to {
                bytes.extend_from_slice(&chunk.bytes()[from..to]);
            }
        }
        Ok(bytes)
    }

    /// Switches initcode buffers between instructions without executing or charging padding.
    #[inline]
    pub(crate) fn advance_initcode_pc(&mut self, pc: &mut Pc) {
        self.0.code.advance_initcode_pc(pc);
    }
}

/// A required payload unexpectedly absent from a custom host implementation.
#[derive(Debug, thiserror::Error)]
#[error("missing required runtime chunk {index} for {address}")]
struct MissingRuntimeChunk {
    address: Address,
    index: u32,
}

#[cfg(test)]
mod tests;
