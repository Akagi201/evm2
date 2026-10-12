# TIP-1143 EVM2 integration contract

This is an opt-in, unscheduled draft. It does not select an activation date or certify production replay, storage compatibility, or gas calibration. Both the default Ethereum authorization policy and Tempo's authorization hook remain available.

## Logical code and stored chunks

Build with the opt-in `account-ext` Cargo feature to enable account extensions and TIP-1143 configuration. `Version::with_tip1143(bool)` controls only `EvmFeatures::TIP1143`. Set `Version::max_code_size` and `Version::max_initcode_size` explicitly; toggling the feature preserves those values. `CODE_CHUNK_SIZE` fixes the logical runtime slice size at 24,540 bytes (`24 KiB - 36`), with a format capacity of 40 slices and 981,600 bytes in total. The draft limits are available as `bytecode::MAX_CODE_SIZE` and `bytecode::MAX_INITCODE_SIZE`; initcode's limit is 2,097,152 bytes (2 MiB). Initcode is analyzed and executed as one complete bytecode buffer. Chunk tariffs are provisionally 28,680 cold and 1,000 warm gas.

```rust
let mut version = Version::base(SpecId::OSAKA).with_tip1143(true);
version.max_code_size = evm2::bytecode::MAX_CODE_SIZE;
version.max_initcode_size = evm2::bytecode::MAX_INITCODE_SIZE;
```

Each prepared chunk has this stored format:

```text
| original code: at most 24,540 bytes | padding: exactly 32 bytes | STOP or RJUMP: 1 or 3 bytes | start offset: 1 byte |
```

A full chunk with a transfer occupies exactly 24 KiB. The final chunk may contain less original code. Ordinary legacy records are unchanged and have no trailer. Bytecode adds its usual in-memory safety padding separately; that safety padding is not stored or hashed.

The complete logical code determines the account hash, code size, deposit gas, copy results and RPC output. Ordered chunk hashes commit to the complete stored buffers, including padding, generated tails and the offset byte. Creation or ingestion prepares the buffers before publication; `code_metadata` computes their commitments and `code_chunk(&Bytes, index)` derives one buffer from complete logical code.

`CodeChunk` owns one `Bytecode` plus scalar preparation context. Bytes, memory safety padding, jump analysis and the cached chunk hash belong to that Bytecode. There is no separate original-byte buffer or per-entry execution variant. `Bytecode::new_chunk(bytes)` validates the stored layout before adding safety padding and lazily analyzes jumps starting at the last stored byte’s offset. `CodeChunk::from_prepared(bytecode, code_size, index)` attaches and validates account context without copying bytes or repeating analysis; providers authenticate them against the account's commitments at ingestion.

Preparation recognizes PUSH1 through PUSH32, the two-byte operands of RJUMP/RJUMPI and the one-byte operands of DUPN/SWAPN/EXCHANGE. Any immediate crossing a boundary is copied into the beginning of the preceding chunk's 32-byte padding field. Missing immediate bytes at the end of the contract are zero-filled. The original bytes at the start of the next chunk remain unchanged. Its final offset byte records how many of those bytes belong to the preceding instruction (`0..32`); jump analysis starts after them.

Unused padding is executable: with at least four bytes available it contains `RJUMP`, its two-byte operand, zero filler and a final `JUMPDEST`. The jump skips the filler and performs a normal destination check within the current physical buffer. With one to three bytes available it contains that many `JUMPDEST`s. Thus padding costs `min(unused bytes, 3)` gas, preserves the stack and adds no chunk reads. The interpreter's opcode loop needs no boundary checks.

The tail is `RJUMP -35` (`e0 5a 38`) when another logical instruction follows, otherwise STOP. The displacement accounts for the fixed 32-byte padding and the three-byte jump. Only this authenticated final RJUMP bypasses JUMPDEST validation: it loads the next chunk and uses that chunk's offset byte to select its first real opcode. A data-only final chunk need not be loaded by fallthrough. Inspectors omit generated padding and tails.

JUMP, taken JUMPI, ordinary RJUMP and taken RJUMPI require a JUMPDEST in the logical payload. Leading immediate bytes are never valid destinations, even when their value is `0x5b`. Ordinary jumps cannot address another chunk's padding through logical positions. There is no runtime bytecode rewriting based on entry offset.

`RJUMP` (`0xe0`) costs 2 gas and uses two EIP-8024-encoded immediate bytes. Each byte belongs to the DUPN/SWAPN alphabet `00..5a` or `80..ff`: decode with `decode_single`, subtract 17, and combine as `high * 219 + low`; values above 23980 subtract 47961. The signed range is -23980 through +23980, relative to the logical PC after the three-byte instruction. Ordinary targets must be inside logical code. Both relative opcodes are unknown unless TIP-1143 is enabled, including initcode.

The bytecode kind explicitly distinguishes legacy records from prepared chunks; a trailer is never inferred from length or content. Human-readable serde keeps ordinary bytecode as hex and encodes chunks as `{ "chunk": "0x..." }`. Binary serde now tags every bytecode kind, changing the previous untagged binary format. Both formats rebuild analysis lazily after decoding.

`bytecode()` returns the shared Bytecode. `bytes()` returns its stored bytes without memory safety padding; `payload_len()` excludes the 32-byte padding, tail and offset byte.

CODECOPY and EXTCODECOPY copy original payload positions directly, excluding all appended fields. They do not fetch a predecessor to reconstruct leading data. Each intersecting chunk is loaded once with its cold read gated by the remaining gas, then charged using the returned coldness. Failures propagate as usual; zero-length and out-of-range copies load no chunks.

## Account types and delegation

`AccountInfo::extension` is available with the optional `account-ext` Cargo feature and is the only source of TIP-1143 account code type. It retains `Option<ThinArc<(), u8>>`: empty extensions allocate nothing, nonempty extensions share a single encoded allocation, and the account field occupies one pointer. Builds without `account-ext` retain the ordinary account layout and do not depend on triomphe. `account-ext` also works without the default features.

- Empty extension: ordinary code, with emptiness determined by `code_hash`.
- Version 1: `AccountExtension::chunked(CodeMetadata)` contains the last chunk size and ordered prepared-buffer hashes. Metadata validates a last chunk size in `1..=24540` and 2 through 40 hashes; the full logical size is derived from these fields.
- Version 2: `AccountExtension::delegated(Address)` contains the delegation target. The ordinary account code hash commits to its marker.

`AccountExtension::encode` emits empty bytes, `1 || last_chunk_size_be_u32 || chunk_hashes`, or `2 || target_20_bytes`. The last chunk size is in `1..=CODE_CHUNK_SIZE`; the full code size is `(chunk_hashes.len() - 1) * CODE_CHUNK_SIZE + last_chunk_size`. `decode` rejects unknown versions, invalid sizes/counts, malformed lengths and zero delegation targets. Serde uses this byte encoding and omits empty extensions from account records. Client account/trie codecs must preserve the selected type and commitments.

`AccountInfo::code_metadata()` returns a borrowed `CodeMetadataRef` over the extension: bytes 1–4 hold the big-endian last chunk size, and each following 32-byte entry holds one hash. `delegation_target()` reads the 20 bytes after the type byte. These accesses do not allocate or decode into an owned enum. `inline_delegation_code()` validates the target and marker hash, then synthesizes the marker without payload I/O or a chunk tariff. Providers must normalize historical delegation records into version 2 metadata when loading accounts. There is no execution-time kind lookup or fallback to a cached bytecode kind. Only one delegation hop is followed.

`CodeChunk::from_bytecode` preserves existing analysis and kind. `CodeChunk::new` treats bytes as legacy instructions, including delegation-shaped prefixes. `AccountHandle::set_chunked_code` explicitly selects version 1 when needed; `set_code_slow` does not infer chunking from size. Installing delegation code selects version 2. Replacing or clearing code replaces the extension.

Code setters, `set_extension`, and `set_info` invalidate account-local chunks immediately when code identity changes. No public account mutation method exposes an unrestricted mutable `AccountInfo`. Handle drop only journals its snapshot; rollback restores the account, cached chunks and warmth together.

## Provider and cache contract

Typed, erased, counted and asynchronous database interfaces require `get_code_chunk_by_hash(chunk_hash) -> Result<Option<Bytecode>, Error>`. Account metadata selects the chunk hash by logical index. The provider returns shared bytecode constructed with `Bytecode::new_chunk`; the state loader supplies the account's complete size and requested index to `CodeChunk::from_prepared`. Code type comes from `get_account`; legacy code uses `get_code_by_hash`. There is no full-code fallback for chunk requests. Providers authenticate content at ingestion; execution validates preparation context without rehashing every payload.

Legacy account execution uses the explicit `get_code_by_hash` record operation after reserving its chunk-zero gas. This preserves an unchanged 24,576-byte legacy record even if another account with the same hash uses the new stride. The selected account representation, not descriptor presence or payload length, chooses the operation. Chunked requests must not use a cached full original record to hide missing prepared data.

`Cache::insert_code` records original code without automatically splitting historical records. Account insertion publishes prepared chunks only when account metadata selects that representation. Creation prepares its chunks before publication. Original and prepared caches retain immutable data across transaction reset and revert.

Persisted buffers and the provider bytecode cache are keyed by chunk hash, so identical buffers and their lazy jump tables are shared across contracts and logical positions. Copy-only reads do not force jump analysis. Prepared hashes include the fixed padding, tails and offset bytes. Account state caches validated `CodeChunk` values by index, with transaction warmth stored alongside them. Each loaded `CodeChunk` shares its Bytecode allocation and analysis with the interpreter; its scalar context identifies the logical index and complete code size.

`State::load_code_chunk(address, index, skip_cold)` returns a `CodeChunkHandle` after checking bounds, payload length and preparation context. Loading does not change warmth or record a journal entry. The handle exposes `get()` and `is_warm()`; `warm()` marks access and journals the cold-to-warm transition, returning whether the chunk was cold. Rollback restores warmth while retaining cached bytes, as it does for storage reads. A cold load with `skip_cold` returns `ColdLoadSkipped` before fetching or warming, including cached chunks made cold by rollback. `Host::load_code_chunk(address, index, skip_cold)` warms the handle and returns `CodeChunkLoad { chunk, is_cold }`, mapping a skipped cold access to out-of-gas. Interpreter and transaction callers pay the warm charge first, set `skip_cold` when the remaining gas cannot cover the cold premium, then charge that premium only for a cold result. Each chunk is looked up once; range copies load and charge sequentially. An unaffordable later chunk is skipped, while frame rollback restores warmth for earlier reads and retains their cached bytes. Missing required data and corruption become node errors, never empty bytecode or EVM halts. Rejected payloads are never published as executable account chunks. Provider cache repair is outside the database interface. Physical residency never determines consensus warmth or price.

Account warmth is keyed by owner and index. Journals restore warmth and code identity at rollback; transaction clearing resets logical warmth while retaining immutable bytes.

## Execution and client handoff

`MessageExt::code` is a `CodeSource` with two variants: `Direct(Bytecode)` for complete bytecode, including transaction and CREATE/CREATE2 initcode, and `Account(CodeChunk)` for an account's entry buffer. Direct bytecode carries its complete original input and analysis; it needs no chunk size or index.

Code ownership is split into three reusable layers:

- `bytecode::CodeChunk` distinguishes a complete `Legacy(Bytecode)` record from a `Prepared(PreparedCodeChunk)` runtime slice. Only the prepared variant stores full runtime size and chunk index; payload length is derived from those fields. Account state and interpreter frames share these immutable buffers and their analysis.
- `evm::state::CodeChunkHandle` loads account chunks and journals warmth. The database handles content hashes; account state handles addresses and indices.
- `interpreter::InterpreterCode` owns the active `CodeSource`, cached borrowed view and PC. It centralizes account chunk activation and pointer lifetimes. Direct code uses its bytecode length; account chunks supply their runtime size, index and tail position.

Recursive calls have independent interpreter cursors. The account owns cached chunks and warmth, never an execution cursor. Returning a frame to the interpreter pool releases its code source.

Large initcode uses ordinary whole-bytecode PUSH analysis and safety padding. It executes directly with no chunk cache, boundary switching or chunk tariffs. Account runtime retains its generated-tail layout and loads subsequent chunks through the host.

Initcode PC and CODESIZE remain global. CODECOPY reads original input bytes directly and zero-fills out-of-range reads through ordinary bytecode copying. Account reads, including EXTCODECOPY and calls made by a constructor, still use account loading and tariffs. Input-word gas, CREATE2 hashing of the entire original input, memory expansion, and copy gas are unchanged. The 2 MiB size ceiling does not override transaction gas caps or the transaction data gas floor; these can impose a lower practical input limit. The complete initcode is temporary; RETURN output alone is validated, charged for deposit, and installed. REVERT, exceptional halts, failed deposit, and enclosing-frame rollback retain ordinary creation semantics.

Both explicit jump opcodes use unchanged global positions. Untaken JUMPI does not read or warm its target. Cross-chunk jumps and internal fallthrough reserve destination gas before I/O. Copy operations read logical payload bytes directly from prepared buffers. Inline marker copies are synthesized from account metadata. Legacy EXTCODECOPY keeps its 24,576-byte source threshold, independent of the new runtime stride.

Draft frames, including initcode, run through the interpreter; JIT/AOT support is deferred. Inspectors must report original PCs and omit internal padding and tails. Creation limits apply through transaction, embedding, CREATE and CREATE2 paths, while ordinary gas, memory and deposit constraints remain.

Reth/Tempo must authenticate ingestion, atomically persist prepared buffers by chunk hash and account metadata, preserve historical state views, reconstruct original RPC bytes, and use one coherent immutable dependency graph. Production inventory, replay, proof growth, provider latency, prepared-buffer costs and final tariff decisions remain activation prerequisites.


`RJUMPI` (`0xe1`) uses the same two-byte offset encoding and costs 4 gas. It pops one condition: nonzero jumps through the shared RJUMP target loader, while zero advances past the immediate. An untaken branch does not validate, load, charge or warm its target chunk; ordinary fallthrough can still cross a chunk boundary and execute a generated RJUMP. Invalid immediate encodings fail even for an untaken branch. Both relative opcodes are unknown when TIP-1143 is disabled.
