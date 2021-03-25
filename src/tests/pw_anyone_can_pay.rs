use super::{eth160, DummyDataLoader, KECCAK256_ALL_ACPL_BIN, MAX_CYCLES, SECP256K1_DATA_BIN};
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgsBuilder},
    prelude::*,
};
use rand::{thread_rng, Rng};

pub const ERROR_ENCODING: i8 = -2;
// pub const ERROR_OVERFLOW: i8 = -41;
pub const ERROR_OUTPUT_AMOUNT_NOT_ENOUGH: i8 = -42;
pub const ERROR_NO_PAIR: i8 = -44;
pub const ERROR_DUPLICATED_INPUTS: i8 = -45;
pub const ERROR_DUPLICATED_OUTPUTS: i8 = -46;

fn gen_tx(dummy: &mut DummyDataLoader, lock_args: Bytes) -> TransactionView {
    let mut rng = thread_rng();
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], &mut rng)
}

fn gen_tx_with_grouped_args<R: Rng>(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    rng: &mut R,
) -> TransactionView {
    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(KECCAK256_ALL_ACPL_BIN.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&KECCAK256_ALL_ACPL_BIN);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, KECCAK256_ALL_ACPL_BIN.clone()),
    );
    // setup secp256k1_data dep
    let secp256k1_data_out_point = {
        let tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(tx_hash, 0)
    };
    let secp256k1_data_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SECP256K1_DATA_BIN.len())
                .expect("data capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        secp256k1_data_out_point.clone(),
        (secp256k1_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    // setup default tx builder

    let block_assembler_code_hash: [u8; 32] = [
        0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1,
        0xb9, 0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3,
        0xcc, 0xe8,
    ];
    let lock_script = Script::new_builder()
        .code_hash(block_assembler_code_hash.pack())
        .args([0u8; 33].pack())
        .hash_type(ScriptHashType::Type.into())
        .build();
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_all_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp256k1_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(lock_script)
                .build(),
        )
        .output_data(Bytes::new().pack());

    for (args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash = {
                let mut buf = [0u8; 32];
                rng.fill(&mut buf);
                buf.pack()
            };
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(sighash_all_cell_data_hash.clone())
                .hash_type(ScriptHashType::Data.into())
                .build();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
            let mut random_extra_witness = [0u8; 32];
            rng.fill(&mut random_extra_witness);
            let witness_args = WitnessArgsBuilder::default()
                .extra(Bytes::from(random_extra_witness.to_vec()).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, 0))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
}

fn build_resolved_tx(data_loader: &DummyDataLoader, tx: &TransactionView) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|dep| {
            let deps_out_point = dep.clone();
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point().clone())
                .build()
        })
        .collect();

    let mut resolved_inputs = Vec::new();
    for i in 0..tx.inputs().len() {
        let previous_out_point = tx.inputs().get(i).unwrap().previous_output();
        let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
        resolved_inputs.push(
            CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                .out_point(previous_out_point)
                .build(),
        );
    }

    ResolvedTransaction {
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs,
        resolved_dep_groups: vec![],
    }
}

fn build_anyone_can_pay_script(args: Bytes) -> Script {
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&KECCAK256_ALL_ACPL_BIN);
    Script::new_builder()
        .args(args.pack())
        .code_hash(sighash_all_cell_data_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

#[test]
fn test_unlock_by_anyone() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass");
}

#[test]
fn test_put_output_data() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .build()])
        .set_outputs_data(vec![Bytes::from(vec![42u8]).pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_ENCODING),
    );
}

#[test]
fn test_wrong_output_args() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash.to_owned());
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock({
                let mut args = pubkey_hash.to_vec();
                // a valid args
                args.push(0);
                script.as_builder().args(Bytes::from(args).pack()).build()
            })
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_NO_PAIR),
    );
}

#[test]
fn test_split_cell() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash.to_owned());
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![
            output
                .clone()
                .as_builder()
                .lock(script.clone())
                .capacity(44u64.pack())
                .build(),
            output
                .as_builder()
                .lock(script)
                .capacity(44u64.pack())
                .build(),
        ])
        .set_outputs_data(vec![
            Bytes::from(Vec::new()).pack(),
            Bytes::from(Vec::new()).pack(),
        ])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_DUPLICATED_OUTPUTS),
    );
}

#[test]
fn test_merge_cell() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let mut rng = thread_rng();
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(pubkey_hash, 2)], &mut rng);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(script.clone())
            .capacity(88u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_DUPLICATED_INPUTS),
    );
}

#[test]
fn test_insufficient_pay() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let script = build_anyone_can_pay_script(pubkey_hash.to_owned());
    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(script.clone())
            .capacity(41u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_OUTPUT_AMOUNT_NOT_ENOUGH),
    );
}

#[ignore]
#[test]
fn test_payment_not_meet_requirement() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);
    let mut args = pubkey_hash.to_vec();
    args.push(1);
    let args = Bytes::from(args);
    let script = build_anyone_can_pay_script(args.clone());
    let tx = gen_tx(&mut data_loader, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(script.clone())
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_OUTPUT_AMOUNT_NOT_ENOUGH),
    );
}

#[test]
fn test_no_pair() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let another_script = build_anyone_can_pay_script(vec![42].into());
    let tx = gen_tx(&mut data_loader, pubkey_hash.to_owned());
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .clone()
            .as_builder()
            .lock(another_script.clone())
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_NO_PAIR),
    );
}

#[ignore]
#[test]
fn test_overflow() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = eth160(pubkey);

    let mut args = pubkey_hash.to_vec();
    args.push(255);
    let args = Bytes::from(args);

    let script = build_anyone_can_pay_script(args.to_owned());
    let tx = gen_tx(&mut data_loader, args);
    let output = tx.outputs().get(0).unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(Vec::new())
        .set_outputs(vec![output
            .as_builder()
            .lock(script)
            .capacity(44u64.pack())
            .build()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    let verify_result = verifier.verify(MAX_CYCLES);

    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_OUTPUT_AMOUNT_NOT_ENOUGH),
    );
}
