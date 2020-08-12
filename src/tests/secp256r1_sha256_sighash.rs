use super::{
    sign_tx_by_input_group_r1, sign_tx_r1, DummyDataLoader, R1_SIGNATURE_SIZE,
    MAX_CYCLES, SECP256R1_SHA256_SIGHASH_BIN, random_r1_key, r1_pub_key
};
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder},
    prelude::*,
};
use rand::{thread_rng, Rng, SeedableRng};

use openssl::pkey::Private;
use openssl::ec::{
    EcKeyRef, 
};
use openssl::ecdsa::EcdsaSig;
use sha2::{Sha256, Digest as SHA2Digest};
use data_encoding::BASE64URL;
use json::object;


const ERROR_ENCODING: i8 = -2;
const ERROR_WITNESS_SIZE: i8 = -22;
const ERROR_PUBKEY_BLAKE160_HASH: i8 = -31;

const ERROR_WRONG_CHALLENGE: i8 = -19;

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
            Capacity::bytes(SECP256R1_SHA256_SIGHASH_BIN.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&SECP256R1_SHA256_SIGHASH_BIN);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, SECP256R1_SHA256_SIGHASH_BIN.clone()),
    );
    // // setup secp256k1_data dep
    // let secp256k1_data_out_point = {
    //     let tx_hash = {
    //         let mut buf = [0u8; 32];
    //         rng.fill(&mut buf);
    //         buf.pack()
    //     };
    //     OutPoint::new(tx_hash, 0)
    // };
    // let secp256k1_data_cell = CellOutput::new_builder()
    //     .capacity(
    //         Capacity::bytes(SECP256K1_DATA_BIN.len())
    //             .expect("data capacity")
    //             .pack(),
    //     )
    //     .build();
    // dummy.cells.insert(
    //     secp256k1_data_out_point.clone(),
    //     (secp256k1_data_cell, SECP256K1_DATA_BIN.clone()),
    // );
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
        // .cell_dep(
        //     CellDep::new_builder()
        //         .out_point(secp256k1_data_out_point)
        //         .dep_type(DepType::Code.into())
        //         .build(),
        // )
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

fn sign_tx_hash(tx: TransactionView, key: &EcKeyRef<Private>, tx_hash: &[u8]) -> TransactionView {
    // calculate message
    let mut hasher = Sha256::default();
    hasher.update(tx_hash);
    let message = hasher.finalize();

    let client_data = object! {
        t: "webauthn.get",
        challenge: BASE64URL.encode(&message),
        origin: "http://localhost:3000",
        crossOrigin: false,
        extra_keys_may_be_added_here: "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
    };
    let client_data_json = client_data.dump();
    let client_data_json_bytes = client_data_json.as_bytes();

    let authr_data:[u8; 37] = [
73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174, 185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99, 1, 0, 0, 0, 2,
    ];

    hasher = Sha256::default();
    hasher.update(&client_data_json);
    let message = hasher.finalize();

    hasher = Sha256::default();
    hasher.update(&authr_data.to_vec());
    hasher.update(&message);
    let message = hasher.finalize();

    let sig = EcdsaSig::sign(&message, &key).unwrap();
    let r = sig.r().to_owned().unwrap().to_vec();
    let s = sig.s().to_owned().unwrap().to_vec();

    let mut lock = [0u8; R1_SIGNATURE_SIZE];
    let data_length= 101 + client_data_json_bytes.len();
    let r_length = r.len();
    let s_length = s.len();
    
    lock[(32-r_length)..32].copy_from_slice(&r);
    lock[(64-s_length)..64].copy_from_slice(&s);
    lock[64..101].copy_from_slice(&authr_data);
    lock[101..data_length].copy_from_slice(&client_data_json_bytes);

    let witness_args = WitnessArgsBuilder::default()
        .lock(lock.to_vec().pack())
        .build();
    tx.as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build()
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

#[test]
fn test_keccak_all_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let tx = sign_tx_r1(&mut data_loader, tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_sighash_all_with_extra_witness_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let extract_witness = vec![1, 2, 3, 4];
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![WitnessArgs::new_builder()
            .extra(Bytes::from(extract_witness).pack())
            .build()
            .as_bytes()
            .pack()])
        .build();
    {
        let tx = sign_tx_r1(&mut data_loader, tx.clone(), &privkey);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        let tx = sign_tx_r1(&mut data_loader, tx, &privkey);
        let wrong_witness = tx
            .witnesses()
            .get(0)
            .map(|w| {
                WitnessArgs::new_unchecked(w.unpack())
                    .as_builder()
                    .extra(Bytes::from(vec![0]).pack())
                    .build()
            })
            .unwrap();
        let tx = tx
            .as_advanced_builder()
            .set_witnesses(vec![wrong_witness.as_bytes().pack()])
            .build();
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_WRONG_CHALLENGE),
        );
    }
}

#[test]
fn test_sighash_all_with_grouped_inputs_unlock() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(pubkey_hash, 2)], &mut rng);
    {
        let tx = sign_tx_r1(&mut data_loader, tx.clone(), &privkey);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        let tx = sign_tx_r1(&mut data_loader, tx.clone(), &privkey);
        let wrong_witness = tx
            .witnesses()
            .get(1)
            .map(|w| {
                WitnessArgs::new_unchecked(w.unpack())
                    .as_builder()
                    .extra(Bytes::from(vec![0]).pack())
                    .build()
            })
            .unwrap();
        let tx = tx
            .as_advanced_builder()
            .set_witnesses(vec![
                tx.witnesses().get(0).unwrap(),
                wrong_witness.as_bytes().pack(),
            ])
            .build();
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_WRONG_CHALLENGE),
        );
    }
}

#[test]
fn test_sighash_all_with_2_different_inputs_unlock() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    // key1
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);
    // key2
    let privkey2 = random_r1_key();
    let pubkey_hash2 = r1_pub_key(&privkey2);

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![(pubkey_hash, 2), (pubkey_hash2, 2)],
        &mut rng,
    );
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey, 0, 2);
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey2, 2, 2);

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_signing_with_wrong_key() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    let wrong_privkey = random_r1_key();

    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let tx = sign_tx_r1(&mut data_loader, tx, &wrong_privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH),
    );
}

#[test]
fn test_signing_wrong_tx_hash() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let tx = {
        let mut rand_tx_hash = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut rand_tx_hash);
        sign_tx_hash(tx, &privkey, &rand_tx_hash[..])
    };
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_WRONG_CHALLENGE),
    );
}

#[test]
fn test_super_long_witness() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);
    let tx = gen_tx(&mut data_loader, pubkey_hash);
    let tx_hash = tx.hash();

    let mut buffer: Vec<u8> = vec![];
    buffer.resize(40000, 1);
    let super_long_message = Bytes::from(&buffer[..]);

    // let mut blake2b = ckb_hash::new_blake2b();
    let mut hasher = Sha256::default();
    // blake2b.update(&tx_hash.raw_data());
    // blake2b.update(&super_long_message[..]);
    // blake2b.finalize(&mut message);
    hasher.update(&tx_hash.raw_data());
    hasher.update(&super_long_message[..]);
    let message = hasher.finalize();

    let sig = EcdsaSig::sign(&message, &privkey).unwrap();
    let r = sig.r().to_owned().unwrap();
    // let s = sig.s().to_owned().unwrap();    

    let witness = WitnessArgs::new_builder()
        .lock(r.to_vec().pack())
        .extra(super_long_message.pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_WITNESS_SIZE),
    );
}

#[test]
fn test_sighash_all_2_in_2_out_cycles() {
    const CONSUME_CYCLES: u64 = 54000000;

    let mut data_loader = DummyDataLoader::new();
    // let mut generator = Generator::non_crypto_safe_prng(42);
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);

    // key1
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);
    // key2
    let privkey2 = random_r1_key();
    let pubkey_hash2 = r1_pub_key(&privkey2);

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![(pubkey_hash, 1), (pubkey_hash2, 1)],
        &mut rng,
    );
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey, 0, 1);
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey2, 1, 1);

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    let cycles = verify_result.expect("pass verification");
    assert_eq!(CONSUME_CYCLES > cycles, true)
}

#[test]
fn test_sighash_all_witness_append_junk_data() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(pubkey_hash, 2)], &mut rng);
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey, 0, 2);
    let mut witnesses: Vec<_> = Unpack::<Vec<_>>::unpack(&tx.witnesses());
    // append junk data to first witness
    let mut witness = Vec::new();
    witness.resize(witnesses[0].len(), 0);
    witness.copy_from_slice(&witnesses[0]);
    witness.push(0);
    witnesses[0] = witness.into();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(witnesses.into_iter().map(|w| w.pack()).collect())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_ENCODING),
    );
}

#[test]
fn test_sighash_all_witness_args_ambiguity() {
    // This test case build tx with WitnessArgs(lock, data, "")
    // and try unlock with WitnessArgs(lock, "", data)
    //
    // this case will fail if contract use a naive function to digest witness.

    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(pubkey_hash, 2)], &mut rng);
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey, 0, 2);
    let witnesses: Vec<_> = Unpack::<Vec<_>>::unpack(&tx.witnesses());
    // move extra data to type_
    let witnesses: Vec<_> = witnesses
        .into_iter()
        .map(|witness| {
            let witness = WitnessArgs::new_unchecked(witness);
            let data = witness.extra().clone();
            witness
                .as_builder()
                .extra(Bytes::new().pack())
                .type_(data)
                .build()
        })
        .collect();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(witnesses.into_iter().map(|w| w.as_bytes().pack()).collect())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_WRONG_CHALLENGE),
    );
}

#[test]
fn test_sighash_all_witnesses_ambiguity() {
    // This test case sign tx with [witness1, "", witness2]
    // and try unlock with [witness1, witness2, ""]
    //
    // this case will fail if contract use a naive function to digest witness.

    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(pubkey_hash, 3)], &mut rng);
    let witness = Unpack::<Vec<_>>::unpack(&tx.witnesses()).remove(0);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witness.pack(),
            Bytes::new().pack(),
            Bytes::from(vec![42]).pack(),
        ])
        .build();
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey, 0, 3);

    // exchange witness position
    let witness = Unpack::<Vec<_>>::unpack(&tx.witnesses()).remove(0);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witness.pack(),
            Bytes::from(vec![42]).pack(),
            Bytes::new().pack(),
        ])
        .build();

    assert_eq!(tx.witnesses().len(), tx.inputs().len());
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_WRONG_CHALLENGE),
    );
}

#[test]
fn test_sighash_all_cover_extra_witnesses() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let privkey = random_r1_key();
    let pubkey_hash = r1_pub_key(&privkey);

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(pubkey_hash, 2)], &mut rng);
    let witness = Unpack::<Vec<_>>::unpack(&tx.witnesses()).remove(0);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witness.pack(),
            Bytes::from(vec![42]).pack(),
            Bytes::new().pack(),
        ])
        .build();
    let tx = sign_tx_by_input_group_r1(&mut data_loader, tx, &privkey, 0, 3);
    assert!(tx.witnesses().len() > tx.inputs().len());

    // change last witness
    let mut witnesses = Unpack::<Vec<_>>::unpack(&tx.witnesses());
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witnesses.remove(0).pack(),
            witnesses.remove(1).pack(),
            Bytes::from(vec![0]).pack(),
        ])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(60000000);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_WRONG_CHALLENGE),
    );
}
