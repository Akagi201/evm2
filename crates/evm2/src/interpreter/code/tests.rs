//! Execution-source switching, initcode boundaries, and inspector equivalence.

use super::*;
use crate::{
    BaseEvmConfigSelector, ExecutionConfig, SpecId, Version,
    bytecode::{Bytecode, CODE_CHUNK_SIZE, MAX_INITCODE_SIZE},
    env::TxEnvExt,
    evm::inspector::Inspector,
    interpreter::{
        InstrStop, Interpreter, InterpreterPool, MessageExt, instructions::encode_rjump_offset, op,
    },
    test_utils::{TestHost, TestTypes},
};
use alloc::vec;
use alloy_primitives::Bytes;

fn compare_initcode(code: Vec<u8>, expected: InstrStop) {
    let bytes = Bytes::from(code);
    let tx = TxEnvExt::default();
    let direct = MessageExt {
        gas_limit: 10_000_000,
        code: Bytecode::new_legacy(bytes.clone()).into(),
        ..Default::default()
    };
    let chunked = MessageExt { code: CodeSource::Initcode(bytes), ..direct.clone() };
    let mut host = TestHost {
        execution_config: ExecutionConfig::for_base_spec::<BaseEvmConfigSelector>(SpecId::OSAKA)
            .with_version(Version::base(SpecId::OSAKA).with_tip1143(true)),
        ..Default::default()
    };
    let mut direct = Interpreter::<TestTypes>::new(&tx, &direct);
    let mut chunked = Interpreter::<TestTypes>::new(&tx, &chunked);
    assert_eq!(direct.run(&mut host).unwrap(), expected);
    assert_eq!(chunked.run(&mut host).unwrap(), expected);
    assert_eq!(chunked.gas().remaining(), direct.gas().remaining());
    assert_eq!(chunked.stack().as_slice(), direct.stack().as_slice());
    assert_eq!(chunked.memory().as_slice(), direct.memory().as_slice());
    assert_eq!(chunked.output(), direct.output());
}

#[test]
fn initcode_fallthrough_preserves_pc_and_gas() {
    let mut code = vec![op::JUMPDEST; CODE_CHUNK_SIZE + 1];
    code.extend([op::PC, op::GAS, op::CODESIZE, op::STOP]);
    compare_initcode(code, InstrStop::Stop);
}

#[test]
fn initcode_crossing_push_and_truncated_immediates() {
    for continuation in 1..=32 {
        let mut code = vec![op::JUMPDEST; CODE_CHUNK_SIZE - (33 - continuation)];
        code.push(op::PUSH32);
        code.extend([op::JUMPDEST; 32]);
        code.extend([op::PC, op::GAS, op::STOP]);
        compare_initcode(code, InstrStop::Stop);
    }
    let mut code = vec![op::JUMPDEST; CODE_CHUNK_SIZE - 1];
    code.extend([op::PUSH32, 0x12]);
    compare_initcode(code, InstrStop::Stop);
}

#[test]
fn initcode_jumps_forward_and_back() {
    let target = 3 * CODE_CHUNK_SIZE;
    let mut code = vec![op::STOP; target + 7];
    code[..10].copy_from_slice(&[
        op::PUSH3,
        (target >> 16) as u8,
        (target >> 8) as u8,
        target as u8,
        op::JUMP,
        op::JUMPDEST,
        op::PC,
        op::GAS,
        op::STOP,
        op::STOP,
    ]);
    code[target..].copy_from_slice(&[
        op::JUMPDEST,
        op::PC,
        op::PUSH1,
        5,
        op::JUMP,
        op::INVALID,
        op::STOP,
    ]);
    compare_initcode(code, InstrStop::Stop);
}

#[test]
fn initcode_rejects_jump_into_continued_push() {
    let target = CODE_CHUNK_SIZE;
    let mut code = vec![op::STOP; target + 33];
    code[..4].copy_from_slice(&[op::PUSH2, (target >> 8) as u8, target as u8, op::JUMP]);
    code[target - 1] = op::PUSH32;
    code[target] = op::JUMPDEST;
    compare_initcode(code, InstrStop::InvalidJump);
}

#[test]
fn initcode_untaken_jump_does_not_validate_destination() {
    let mut code = vec![op::INVALID; MAX_INITCODE_SIZE];
    code[..5].copy_from_slice(&[op::PUSH0, op::PUSH1, 99, op::JUMPI, op::STOP]);
    compare_initcode(code, InstrStop::Stop);
}

#[test]
fn initcode_relative_jump_crosses_boundary() {
    let mut code = vec![op::JUMPDEST; CODE_CHUNK_SIZE - 1];
    code.push(op::RJUMP);
    code.extend(encode_rjump_offset(1).unwrap());
    code.extend([op::INVALID, op::JUMPDEST, op::PC, op::GAS, op::STOP]);
    compare_initcode(code, InstrStop::Stop);
}

#[test]
fn initcode_codecopy_reads_original_bytes_and_zero_fills() {
    for offset in [CODE_CHUNK_SIZE - 16, MAX_INITCODE_SIZE - 16, MAX_INITCODE_SIZE + 1] {
        let mut code = vec![0xab; MAX_INITCODE_SIZE];
        code[..13].copy_from_slice(&[
            op::PUSH1,
            64,
            op::PUSH3,
            (offset >> 16) as u8,
            (offset >> 8) as u8,
            offset as u8,
            op::PUSH0,
            op::CODECOPY,
            op::PUSH1,
            64,
            op::PUSH0,
            op::RETURN,
            op::STOP,
        ]);
        compare_initcode(code, InstrStop::Return);
    }
}

#[test]
fn initcode_preserves_legacy_jump_analysis_inside_invalid_relative_immediates() {
    for (target, operand, expected) in [
        (CODE_CHUNK_SIZE + 1, op::STOP, InstrStop::Stop),
        (CODE_CHUNK_SIZE + 20, op::PUSH32, InstrStop::InvalidJump),
    ] {
        let mut code = vec![op::STOP; CODE_CHUNK_SIZE + 40];
        code[..4].copy_from_slice(&[op::PUSH2, (target >> 8) as u8, target as u8, op::JUMP]);
        code[CODE_CHUNK_SIZE - 1] = op::RJUMP;
        code[CODE_CHUNK_SIZE] = operand;
        code[target] = op::JUMPDEST;
        compare_initcode(code, expected);
    }
}

#[derive(Default)]
struct InitcodeTrace(Vec<(bool, usize, u64)>);

impl Inspector<TestTypes> for InitcodeTrace {
    fn step(&mut self, interp: &mut Interpreter<'_, '_, TestTypes>) {
        self.0.push((false, interp.pc(), interp.gas().remaining()));
    }

    fn step_end(&mut self, interp: &mut Interpreter<'_, '_, TestTypes>) {
        self.0.push((true, interp.pc(), interp.gas().remaining()));
    }
}

#[test]
fn initcode_inspector_trace_matches_direct_execution() {
    let mut code = vec![op::JUMPDEST; CODE_CHUNK_SIZE - 1];
    code.extend([op::PUSH2, 0x12, 0x34, op::PC, op::GAS, op::STOP]);
    let bytes = Bytes::from(code);
    let tx = TxEnvExt::default();
    let direct = MessageExt {
        gas_limit: 100_000,
        code: Bytecode::new_legacy(bytes.clone()).into(),
        ..Default::default()
    };
    let chunked = MessageExt { code: CodeSource::Initcode(bytes), ..direct.clone() };
    let mut host = TestHost::default();
    let mut expected = InitcodeTrace::default();
    let mut actual = InitcodeTrace::default();
    let mut direct = Interpreter::<TestTypes>::new(&tx, &direct);
    let mut chunked = Interpreter::<TestTypes>::new(&tx, &chunked);
    assert_eq!(chunked.original_bytecode_hash(), direct.original_bytecode_hash());
    assert_eq!(direct.run_inspect(&mut host, &mut expected).unwrap(), InstrStop::Stop);
    assert_eq!(chunked.run_inspect(&mut host, &mut actual).unwrap(), InstrStop::Stop);
    assert_eq!(actual.0, expected.0);
}

#[test]
fn pooled_frames_switch_between_account_initcode_and_direct_sources() {
    let target = CODE_CHUNK_SIZE;
    let mut bytes = vec![op::STOP; target + 4];
    bytes[..4].copy_from_slice(&[op::PUSH2, (target >> 8) as u8, target as u8, op::JUMP]);
    bytes[target..].copy_from_slice(&[op::JUMPDEST, op::PC, op::CODESIZE, op::STOP]);
    let bytes = Bytes::from(bytes);
    let small = Bytes::from_static(&[op::PC, op::CODESIZE, op::STOP]);
    let large_result = [Word::from(target + 1), Word::from(bytes.len())];
    let small_result = [Word::ZERO, Word::from(small.len())];
    let cases = [
        (CodeSource::Initcode(bytes.clone()), large_result.as_slice()),
        (Bytecode::new_legacy(small.clone()).into(), small_result.as_slice()),
        (
            CodeSource::Account(crate::bytecode::code_chunk(&bytes, 0).unwrap()),
            large_result.as_slice(),
        ),
        (CodeSource::Initcode(small), small_result.as_slice()),
        (CodeSource::default(), &[]),
    ];
    let mut host = TestHost {
        code: bytes,
        execution_config: ExecutionConfig::for_base_spec::<BaseEvmConfigSelector>(SpecId::OSAKA)
            .with_version(Version::base(SpecId::OSAKA).with_tip1143(true)),
        ..Default::default()
    };
    let tx = TxEnvExt::default();
    let mut pool = InterpreterPool::<TestTypes>::new();
    for _ in 0..2 {
        for (code, expected) in &cases {
            let message =
                MessageExt { code: code.clone(), gas_limit: 100_000, ..Default::default() };
            let mut frame = pool.pop(&tx, &message);
            assert_eq!(frame.pc(), 0);
            assert_eq!(frame.run(&mut host).unwrap(), InstrStop::Stop);
            assert_eq!(frame.stack().as_slice(), *expected);
            pool.push(frame);
        }
    }
}
