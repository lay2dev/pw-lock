mod anyone_can_pay;
mod secp256k1_keccak256_sighash_all;
mod secp256k1_keccak256_sighash_all_acpl_compatibility;
mod secp256k1_ripemd160_sha256_sighash_all;


use bech32::{self, ToBase32};
use ckb_crypto::secp::{Privkey, Pubkey};
use ckb_fixed_hash::{H160, H512};
use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{cell::CellMeta, BlockExt, EpochExt, HeaderView, TransactionView},
    packed::{
        self, Byte32, CellInputVec, CellOutput, CellOutputVec, OutPoint, Script, WitnessArgs,
    },
    prelude::*,
    H256,
};
use secp256k1::{SecretKey, key};

use lazy_static::lazy_static;
use sha2::Sha256;
use std::collections::HashMap;

use sha3::{Digest, Keccak256};

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

lazy_static! {
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_data")[..]);
    pub static ref KECCAK256_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_keccak256_sighash_all")[..]);
    pub static ref KECCAK256_ALL_ACPL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_keccak256_sighash_all_acpl")[..]);
    pub static ref RIPEMD160_SHA256_ALL_BIN: Bytes = Bytes::from(
        &include_bytes!("../../specs/cells/secp256k1_ripemd160_sha256_sighash_all")[..]
    );
    pub static ref RIPEMD160_SHA256_ALL_ACPL_BIN: Bytes = Bytes::from(
        &include_bytes!("../../specs/cells/secp256k1_ripemd160_sha256_sighash_all")[..]
    );
    pub static ref CKB_CELL_UPGRADE_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/ckb_cell_upgrade")[..]);
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
    pub epoches: HashMap<Byte32, EpochExt>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl DataLoader for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<(Bytes, Byte32)> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| (data.clone(), CellOutput::calc_data_hash(&data)))
        })
    }
    // load BlockExt
    fn get_block_ext(&self, _hash: &Byte32) -> Option<BlockExt> {
        unreachable!()
    }

    // load header
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }

    // load EpochExt
    fn get_block_epoch(&self, block_hash: &Byte32) -> Option<EpochExt> {
        self.epoches.get(block_hash).cloned()
    }
}


#[derive(Copy, Clone)]
pub enum SigType {
    Recoverable,
    NonRecoverable,
}

impl SigType {
    pub fn signature_size(self) -> usize {
        match self {
            SigType::Recoverable => 65,
            SigType::NonRecoverable => 64,
        }
    }
}

fn ripemd160(data: &[u8]) -> H160 {
    use ripemd160::Ripemd160;
    let digest: [u8; 20] = Ripemd160::digest(data).into();
    H160::from(digest)
}

fn sha256(data: &[u8]) -> H256 {
    let digest: [u8; 32] = Sha256::digest(data).into();
    H256::from(digest)
}

fn pubkey_uncompressed(pubkey: &Pubkey) -> Vec<u8> {
    let mut serialized = vec![4u8; 65];
    serialized[1..65].copy_from_slice(pubkey.as_ref());
    serialized
}

fn pubkey_compressed(pubkey: &Pubkey) -> Vec<u8> {
    pubkey.serialize()
}

fn ripemd_sha(serialized_pubkey: &[u8]) -> Vec<u8> {
    ripemd160(sha256(serialized_pubkey).as_bytes())
        .as_ref()
        .to_owned()
}

// pub fn eth160(message: &[u8]) -> Bytes {
pub fn eth160(pubkey1: Pubkey) -> Bytes {
    let prefix_key: [u8; 65] = {
        let mut temp = [4u8; 65];
        let h512: H512 = pubkey1.into();
        temp[1..65].copy_from_slice(h512.as_bytes());
        temp
    };
    let pubkey = key::PublicKey::from_slice(&prefix_key).unwrap();
    let message = Vec::from(&pubkey.serialize_uncompressed()[1..]);
    // let message = Vec::from(&pubkey.serialize()[..]);

    // println!("{}", faster_hex::hex_string(&message).unwrap());
    // println!("{}", faster_hex::hex_string(&message1).unwrap());

    let mut hasher = Keccak256::default();
    hasher.input(&message);
    Bytes::from(hasher.result().as_slice()).slice(12, 32)
}

pub fn sign_tx_keccak256(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    key: &Privkey,
) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group_keccak256(dummy, tx, key, 0, witnesses_len)
}

pub fn sign_tx_by_input_group_keccak256(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                // let mut blake2b = ckb_hash::new_blake2b();
                let mut hasher = Keccak256::default();
                let mut message = [0u8; 32];

                // blake2b.update(&tx_hash.raw_data());
                hasher.input(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                // blake2b.update(&witness_len.to_le_bytes());
                // blake2b.update(&witness_for_digest.as_bytes());
                hasher.input(&witness_len.to_le_bytes());
                hasher.input(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    // blake2b.update(&witness_len.to_le_bytes());
                    // blake2b.update(&witness.raw_data());
                    hasher.input(&witness_len.to_le_bytes());
                    hasher.input(&witness.raw_data());
                });
                // blake2b.finalize(&mut message);
                message.copy_from_slice(&hasher.result()[0..32]);

                let prefix: [u8; 28] = [
                    0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69, 0x67,
                    0x6e, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a,
                    0x33, 0x32,
                ];
                hasher = Keccak256::default();
                hasher.input(&prefix);
                hasher.input(&message);
                message.copy_from_slice(&hasher.result()[0..32]);

                // let message = H256::from(message);
                let message = get_tx_typed_data_hash(dummy, message, tx.inputs(), tx.outputs());
                let sig = key.sign_recoverable(&message).expect("sign");
                witness
                    .as_builder()
                    .lock(sig.serialize().pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn get_tx_typed_data_hash(
    dummy: &mut DummyDataLoader,
    tx_hash: [u8; 32],
    inputs: CellInputVec,
    outputs: CellOutputVec,
) -> H256 {
    let mut message = [0u8; 32];
    let typeddata_prefix: [u8; 2] = [0x19, 0x01];
    let ckbtransaction_typehash: [u8; 32] = [
        0x17, 0xe4, 0x04, 0xd0, 0xcd, 0xcc, 0x43, 0x1e, 0xe6, 0xdf, 0x80, 0x7a, 0xbc, 0xcc, 0x69,
        0x5d, 0x95, 0xd0, 0x38, 0xf5, 0x76, 0x47, 0xe2, 0xef, 0x92, 0xb9, 0x68, 0x66, 0xca, 0xe5,
        0x9d, 0x04,
    ];
    let output_typehash: [u8; 32] = [
        0xef, 0xdd, 0x9a, 0xc6, 0xc9, 0x8f, 0xcb, 0xab, 0xc5, 0x2e, 0xf1, 0xd8, 0xa4, 0xd3, 0xac,
        0xcd, 0x43, 0x96, 0x36, 0x2a, 0x21, 0x1c, 0xbf, 0x7a, 0x3c, 0x20, 0xc2, 0x89, 0x22, 0x08,
        0x19, 0x13,
    ];
    let domain_separator: [u8; 32] = [
        0xec, 0x9e, 0x64, 0xcb, 0x49, 0x31, 0x37, 0x85, 0x0e, 0x3d, 0x5d, 0x47, 0x3c, 0xa1, 0x09,
        0xea, 0xe1, 0x47, 0xad, 0xb8, 0xa6, 0xbf, 0x46, 0x0b, 0xf2, 0x06, 0xe9, 0x0f, 0x62, 0x64,
        0x2e, 0x3f,
    ];

    let mut hasher = Keccak256::default();

    let mut input_capacities: u64 = 0;
    let len = inputs.len();
    (0..len).for_each(|n| {
        let input_cell = inputs.get(n).unwrap();
        let previous_outpoint = input_cell.previous_output();
        let val = dummy.cells.get(&previous_outpoint);
        let (cell, _) = val.unwrap();

        let capacity = cell.capacity();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(capacity.as_slice());
        let c64 = u64::from_le_bytes(bytes);
        input_capacities += c64;
    });

    println!("input capacities {}", input_capacities);

    let mut output_capacities: u64 = 0;

    let len = outputs.len();
    (0..len).for_each(|n| {
        let output_cell = outputs.get(n).unwrap();
        let capacity = output_cell.capacity();

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(capacity.as_slice());
        let c64 = u64::from_le_bytes(bytes);
        output_capacities += c64;

        let mut output_hasher = Keccak256::default();
        output_hasher.input(&output_typehash);

        output_hasher.input(&hash_address(output_cell.lock()));
        output_hasher.input(&hash_amount(c64));

        hasher.input(&output_hasher.result());
    });

    let output_hash = hasher.result();

    hasher = Keccak256::default();
    hasher.input(&ckbtransaction_typehash);
    hasher.input(&tx_hash);
    hasher.input(&hash_amount(input_capacities - output_capacities));
    hasher.input(&hash_amount(input_capacities));
    hasher.input(&output_hash);

    let ckb_type_hash = hasher.result();

    hasher = Keccak256::default();
    hasher.input(&typeddata_prefix);
    hasher.input(&domain_separator);
    hasher.input(&ckb_type_hash);

    message.copy_from_slice(&hasher.result()[0..32]);

    H256::from(message)
}

pub fn hash_amount(amount: u64) -> [u8; 32] {
    let mut message = [0u8; 32];
    let formated_capacity = format!("{:.8}CKB", (amount as f64) / 100000000.0);

    println!(
        "formated_capacity: {}, {}, {}",
        amount,
        formated_capacity,
        formated_capacity.len()
    );
    let mut capacity_hasher = Keccak256::default();
    capacity_hasher.input(&formated_capacity.as_bytes());
    message.copy_from_slice(&capacity_hasher.result()[0..32]);
    message
}

pub fn hash_address(lock: Script) -> [u8; 32] {
    let mut message = [0u8; 32];

    let args = lock.args();
    let code_hash = lock.code_hash();
    let hash_type = lock.hash_type();
    let ckb_address: String;
    if code_hash.raw_data().to_vec().eq(&[0u8; 32]) {
        ckb_address = String::from("unknown");
    } else {
        let secp256k1_blake160_sighash_all_type_hash: [u8; 32] = [
            0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23,
            0xf1, 0xb9, 0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b,
            0xbd, 0xa3, 0xcc, 0xe8,
        ];
        let secp256k1_blake160_multisig_all_type_hash: [u8; 32] = [
            0x5c, 0x50, 0x69, 0xeb, 0x08, 0x57, 0xef, 0xc6, 0x5e, 0x1b, 0xca, 0x0c, 0x07, 0xdf,
            0x34, 0xc3, 0x16, 0x63, 0xb3, 0x62, 0x2f, 0xd3, 0x87, 0x6c, 0x87, 0x63, 0x20, 0xfc,
            0x96, 0x34, 0xe2, 0xa8,
        ];

        let mut prefix;
        if code_hash
            .raw_data()
            .to_vec()
            .eq(&secp256k1_blake160_sighash_all_type_hash)
        {
            prefix = vec![0x01, 0x00];
        } else if code_hash
            .raw_data()
            .to_vec()
            .eq(&secp256k1_blake160_multisig_all_type_hash)
        {
            prefix = vec![0x01, 0x01];
        } else {
            if hash_type.as_bytes()[0] == 0x01 {
                prefix = vec![0x04];
            } else {
                prefix = vec![0x02];
            }
            prefix.extend(&code_hash.raw_data());
        }
        prefix.extend(&args.raw_data());
        let address = bech32::encode("ckt", prefix.to_base32()).unwrap();

        if address.len() <= 17 {
            ckb_address = address;
        } else {
            ckb_address = format!("{}...{}", &address[0..7], &address[(address.len() - 7)..]);
        }
    }

    let mut address_hasher = Keccak256::default();
    address_hasher.input(&ckb_address.as_bytes());
    message.copy_from_slice(&address_hasher.result()[0..32]);
    message
}

// Special signature method, inconsistent with the default lock behavior,
// witness signature only sign transaction hash
pub fn sign_tx(tx: TransactionView, key: &SecretKey) -> TransactionView {
    sign_tx_by_input_group(tx, key, 0, 0, SigType::Recoverable)
}
pub fn sign_tx_by_input_group(
    tx: TransactionView,
    key: &SecretKey,
    begin_index: usize,
    len: usize,
    sig_type: SigType,
) -> TransactionView {
    let tx_hash: H256 = tx.hash().unpack();
    let signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            // digest the first witness
            if i == begin_index {
                let mut hasher = sha2::Sha256::new();
                hasher.input(&tx_hash);
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(sig_type.signature_size(), 0);
                    buf.extend_from_slice(&Unpack::<Bytes>::unpack(&witness.lock()));
                    buf.into()
                };
                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                hasher.input(&witness_len.to_le_bytes());
                hasher.input(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    hasher.input(&witness_len.to_le_bytes());
                    hasher.input(&witness.raw_data());
                });
                let mut message = [0u8; 32];
                message.copy_from_slice(&hasher.result());
                let sig = match sig_type {
                    SigType::Recoverable => {
                        let message = H256::from(message);
                        let key = Privkey::from_slice(&key[..]);
                        key.sign_recoverable(&message).expect("sign").serialize()
                    }
                    SigType::NonRecoverable => {
                        let context = &ckb_crypto::secp::SECP256K1;
                        let message = secp256k1::Message::from_slice(&message).unwrap();
                        // let key = secp256k1::key::SecretKey::from_slice(key.as_bytes()).unwrap();
                        let signature = context.sign(&message, &key);
                        signature.serialize_compact().to_vec()
                    }
                };
                assert_eq!(sig_type.signature_size(), sig.len());
                let lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&sig);
                    buf.extend_from_slice(&zero_lock[sig_type.signature_size()..]);
                    buf.into()
                };
                witness
                    .as_builder()
                    .lock(lock.pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap()
            }
        })
        .collect();
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

// Special signature method, inconsistent with the default lock behavior,
// witness signature only sign transaction hash
pub fn sign_tx_without_pubkey(tx: TransactionView, key: &SecretKey) -> TransactionView {
    sign_tx_by_input_group_without_pubkey(tx, key, 0, 0, SigType::Recoverable)
}

pub fn sign_tx_by_input_group_without_pubkey(
    tx: TransactionView,
    key: &SecretKey,
    begin_index: usize,
    len: usize,
    sig_type: SigType,
) -> TransactionView {
    let tx_hash: H256 = tx.hash().unpack();
    let signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            // digest the first witness
            if i == begin_index {
                let mut hasher = sha2::Sha256::new();
                hasher.input(&tx_hash);
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(sig_type.signature_size(), 0);
                    buf.into()
                };
                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                hasher.input(&witness_len.to_le_bytes());
                hasher.input(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    hasher.input(&witness_len.to_le_bytes());
                    hasher.input(&witness.raw_data());
                });
                let mut message = [0u8; 32];
                message.copy_from_slice(&hasher.result());
                let sig = match sig_type {
                    SigType::Recoverable => {
                        let message = H256::from(message);
                        let key = Privkey::from_slice(&key[..]);
                        key.sign_recoverable(&message).expect("sign").serialize()
                    }
                    SigType::NonRecoverable => {
                        let context = &ckb_crypto::secp::SECP256K1;
                        let message = secp256k1::Message::from_slice(&message).unwrap();
                        // let key = secp256k1::key::SecretKey::from_slice(key.as_bytes()).unwrap();
                        let signature = context.sign(&message, &key);
                        signature.serialize_compact().to_vec()
                    }
                };
                assert_eq!(sig_type.signature_size(), sig.len());
                let lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&sig);
                    buf.extend_from_slice(&zero_lock[sig_type.signature_size()..]);
                    buf.into()
                };
                witness
                    .as_builder()
                    .lock(lock.pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap()
            }
        })
        .collect();
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}
