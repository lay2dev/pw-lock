use super::{sign_tx, DummyDataLoader, CKB_CELL_UPGRADE_BIN, MAX_CYCLES, SECP256K1_DATA_BIN, SIGHASH_ALL_BIN};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script,  WitnessArgsBuilder},
    prelude::*,
};
use rand::{thread_rng, Rng};


fn script_cell(script_data: &Bytes) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(script_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();

    (cell, out_point)
}

fn secp_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&SIGHASH_ALL_BIN)
}

fn generate_random_out_point() -> OutPoint {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(tx_hash, 0)
}

fn upgrade_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&CKB_CELL_UPGRADE_BIN)
}

fn cell_output_with_type_id(shannons: u64, type_args: Bytes) -> CellOutput {

    let type_ = Script::new_builder()
        // .args(Bytes::new().pack())
        .args(type_args.pack())
        .code_hash(upgrade_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();

    CellOutput::new_builder()
        .type_(Some(type_).pack())
        .capacity(Capacity::shannons(shannons).pack())
        .build()
}

fn dummy_cell_output(shannons: u64) -> CellOutput {

    CellOutput::new_builder()
        .capacity(Capacity::shannons(shannons).pack())
        .build()
}

fn gen_common_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
    data: Bytes,
)-> (CellOutput, OutPoint) {

    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();

    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        .build();

    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), data));

    (cell, out_point)

}

fn gen_upgrade_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
    data: Bytes,
)-> (CellOutput, OutPoint) {

    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    
    let type_ = Script::new_builder()
        .args(Bytes::new().pack())
        .code_hash(upgrade_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();

    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        .type_(Some(type_).pack())
        .build();

    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), data));

    (cell, out_point)

}

fn gen_lock() -> (Privkey, Bytes) {
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let lock_args = pubkey_hash.into();
    (privkey, lock_args)
}

fn complete_tx(
    dummy: &mut DummyDataLoader,
    builder: TransactionBuilder,
) -> (TransactionView, Vec<CellMeta>) {
    let (secp_cell, secp_out_point) = script_cell(&SIGHASH_ALL_BIN);
    let (secp_data_cell, secp_data_out_point) = script_cell(&SECP256K1_DATA_BIN);
    let (upgrade_cell, upgrade_out_point) = script_cell(&CKB_CELL_UPGRADE_BIN);

    let secp_cell_meta =
        CellMetaBuilder::from_cell_output(secp_cell.clone(), SIGHASH_ALL_BIN.clone())
            .out_point(secp_out_point.clone())
            .build();
    let secp_data_cell_meta =
        CellMetaBuilder::from_cell_output(secp_data_cell.clone(), SECP256K1_DATA_BIN.clone())
            .out_point(secp_data_out_point.clone())
            .build();
    let upgrade_cell_meta = CellMetaBuilder::from_cell_output(upgrade_cell.clone(), CKB_CELL_UPGRADE_BIN.clone())
        .out_point(upgrade_out_point.clone())
        .build();

    dummy
        .cells
        .insert(secp_out_point.clone(), (secp_cell, SIGHASH_ALL_BIN.clone()));
    dummy.cells.insert(
        secp_data_out_point.clone(),
        (secp_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    dummy
        .cells
        .insert(upgrade_out_point.clone(), 
        (upgrade_cell, CKB_CELL_UPGRADE_BIN.clone()));

    let tx = builder
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(upgrade_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .build();

    let mut resolved_cell_deps = vec![];
    resolved_cell_deps.push(secp_cell_meta);
    resolved_cell_deps.push(secp_data_cell_meta);
    resolved_cell_deps.push(upgrade_cell_meta);

    (tx, resolved_cell_deps)
}

#[test]
fn test_single_cell_upgrade(){
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (cell, previous_out_point) = gen_upgrade_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
        Bytes::from("hello world")
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from("hello world"))
        .out_point(previous_out_point.clone())
        .build();
    
    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();

    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(cell_output_with_type_id(123468105678, Bytes::new()))
        .output_data(Bytes::from("hello world 1").pack())
        .witness(witness_args.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");



}

#[test]
fn test_upgrade_to_two_outputs(){

    // cell with type_id upgrade to two outputs with same type_id
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (cell, previous_out_point) = gen_upgrade_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
        Bytes::from("hello world")
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from("hello world"))
        .out_point(previous_out_point.clone())
        .build();
    
    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();

    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .outputs([cell_output_with_type_id(123468105678, Bytes::new()), cell_output_with_type_id(123468105678, Bytes::new())].to_vec())
        .outputs_data([Bytes::from("hello world 1").pack(), Bytes::from("hello world 1").pack()].to_vec())
        .witness(witness_args.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(-1),
    );
 }

#[test]
fn test_new_cell_with_wrong_args(){

    // create a data cell with wrong args
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (cell, previous_out_point) = gen_common_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
        Bytes::from("hello world")
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from("hello world"))
        .out_point(previous_out_point.clone())
        .build();
    
    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();

    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .output(cell_output_with_type_id(123468105678, Bytes::new()))
        .output_data(Bytes::from("hello world 1").pack())
        .witness(witness_args.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(-103),
    );
}

#[test]
fn test_new_upgrade_cell(){
    // create a data cell with type_id
    
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (cell, previous_out_point) = gen_common_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
        Bytes::from("hello world")
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from("hello world"))
        .out_point(previous_out_point.clone())
        .build();
    
    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();

    
    let input = CellInput::new(previous_out_point, 0x2003e8022a0002f3);
    let type_args = input.as_bytes();

    let builder = TransactionBuilder::default()
        .input(input)
        .output(cell_output_with_type_id(123468105678, type_args))
        .output_data(Bytes::from("hello world 1").pack())
        .witness(witness_args.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}


#[test]
fn test_upgrade_cell_with_different_args(){
    // create a data cell with type_id
    
    let mut data_loader = DummyDataLoader::new();
    let (_, lock_args) = gen_lock();

    let (_, previous_out_point1) = gen_common_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
        Bytes::from("hello world")
    );
    let input1 = CellInput::new(previous_out_point1, 0x2003e8022a0002f3);
    let type_args = input1.as_bytes();

    let (privkey, lock_args) = gen_lock();
    let (cell, previous_out_point) = gen_upgrade_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
        Bytes::from("hello world")
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from("hello world"))
        .out_point(previous_out_point.clone())
        .build();
    
    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();
    

    let input = CellInput::new(previous_out_point, 0x2003e8022a0002f3);
    let builder = TransactionBuilder::default()
        .input(input)
        .output(cell_output_with_type_id(123468105678, type_args))
        .output_data(Bytes::from("hello world 1").pack())
        .witness(witness_args.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    // verify_result.expect("pass verification");
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(-103),
    );
}


#[test]
fn test_burn_upgrade_cell(){
    // create a data cell with type_id
    
    let mut data_loader = DummyDataLoader::new();
    let (_, lock_args) = gen_lock();

    let (privkey, lock_args) = gen_lock();
    let (cell, previous_out_point) = gen_upgrade_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args,
        Bytes::from("hello world")
    );

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from("hello world"))
        .out_point(previous_out_point.clone())
        .build();
    
    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let mut random_extra_witness = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut random_extra_witness);
    let witness_args = WitnessArgsBuilder::default()
        .extra(Bytes::from(random_extra_witness.to_vec()).pack())
        .build();
    

    let input = CellInput::new(previous_out_point, 0x2003e8022a0002f3);
    let builder = TransactionBuilder::default()
        .input(input)
        .output(dummy_cell_output(123468105678))
        .output_data(Bytes::from("hello world 1").pack())
        .witness(witness_args.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let verify_result = TransactionScriptsVerifier::new(&rtx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}