mod pw_anyone_can_pay;
mod pw_anyone_can_pay_compatibility;
mod secp256r1_sha256_sighash;

use ckb_crypto::secp::{Privkey, Pubkey};
use ckb_fixed_hash::{H160, H512};
use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{cell::CellMeta, BlockExt, EpochExt, HeaderView, TransactionView},
    packed::{
        self, Byte32, CellOutput, OutPoint, WitnessArgs,
    },
    prelude::*,
    H256,
};


use std::env;

use lazy_static::lazy_static;
use sha3::{Digest, Keccak256};
use secp256k1::{ key};

use std::collections::HashMap;

use data_encoding::BASE64URL;
use json::object;
use openssl::{base64, bn::BigNumContext};
use openssl::ec::EcKeyRef;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use sha2::{Digest as SHA2Digest, Sha256};

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;
pub const R1_SIGNATURE_SIZE: usize = 564;
pub const CHAIN_ID_ETH: u8 = 1;
pub const CHAIN_ID_EOS: u8 = 2;
pub const CHAIN_ID_TRON: u8 = 3;
pub const CHAIN_ID_BTC: u8 = 4;
pub const CHAIN_ID_DOGE: u8 = 5;

lazy_static! {
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_data")[..]);
    pub static ref KECCAK256_ALL_ACPL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/pw_anyone_can_pay")[..]);
    pub static ref SECP256R1_SHA256_SIGHASH_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256r1_sha256_sighash")[..]);

}

pub fn get_current_chain_id() -> u8 {
    if let Ok(v) = env::var("CHAIN_ID") {
       let chain_id= u8::from_str_radix(&v, 16).unwrap();
       chain_id 
    } else {
        1
    }
}

pub fn is_compressed() -> bool {
    if let Ok(v) = env::var("COMPRESSED") {
        let id= u8::from_str_radix(&v, 16).unwrap();
        if id >0 {
            true
        } else {
            false
        }
    } else {
        true
    }
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

fn ripemd_sha(serialized_pubkey: &[u8]) -> Bytes {
    Bytes::from(ripemd160(sha256(serialized_pubkey).as_bytes())
        .as_ref()
        .to_owned())
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
    sign_tx_keccak256_with_flag(dummy, tx, key, true)
}

pub fn sign_tx_keccak256_with_flag(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    key: &Privkey,
    set_chain_flag: bool
) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group_keccak256_flag(dummy, tx, key, 0, witnesses_len, set_chain_flag)
}

pub fn sign_tx_by_input_group_keccak256(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    sign_tx_by_input_group_keccak256_flag(dummy, tx, key, begin_index, len, true)
}

pub fn sign_tx_by_input_group_keccak256_flag(
    _: &mut DummyDataLoader,
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
    set_chain_flag: bool
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| -> packed::Bytes {
            if i == begin_index {
                let mut hasher = Keccak256::default();
                let mut message = [0u8; 32];

                let lock_size = match set_chain_flag {
                    true => SIGNATURE_SIZE + 1,
                    false => SIGNATURE_SIZE
                };

                let start_index = match set_chain_flag {
                    true => 1,
                    false => 0
                };

                let end_index = start_index + SIGNATURE_SIZE;

                hasher.input(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(lock_size, 0);
                    buf.into()
                };
                let mut lock =   [0u8; SIGNATURE_SIZE + 1];
                
                lock[0] = get_current_chain_id();

                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                println!("witness_len = {}", witness_len);
                hasher.input(&witness_len.to_le_bytes());
                hasher.input(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    hasher.input(&witness_len.to_le_bytes());
                    hasher.input(&witness.raw_data());
                });
                // blake2b.finalize(&mut message);
                message.copy_from_slice(&hasher.result()[0..32]);

                if get_current_chain_id() == CHAIN_ID_ETH {
                    // Ethereum personal sign prefix \x19Ethereum Signed Message:\n32
                    let prefix: [u8; 28] = [
                        0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69,
                        0x67, 0x6e, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
                        0x3a, 0x0a, 0x33, 0x32,
                    ];
                    hasher = Keccak256::default();
                    hasher.input(&prefix);
                    hasher.input(&message);
                    message.copy_from_slice(&hasher.result()[0..32]);

                    let message1 = H256::from(message);

                    let sig = key.sign_recoverable(&message1).expect("sign");
                    lock[start_index..end_index].copy_from_slice(&sig.serialize().to_vec());
                } else if get_current_chain_id() == CHAIN_ID_TRON {
                    // Tron sign prefix \x19TRON Signed Message:\n32
                    let prefix: [u8; 24] = [
                        0x19, 0x54, 0x52, 0x4f, 0x4e, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
                        0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32,
                    ];
                    hasher = Keccak256::default();
                    hasher.input(&prefix);
                    hasher.input(&message);
                    message.copy_from_slice(&hasher.result()[0..32]);

                    let message1 = H256::from(message);

                    let sig = key.sign_recoverable(&message1).expect("sign");
                    lock[start_index..end_index].copy_from_slice(&sig.serialize().to_vec());
                } else if get_current_chain_id() == CHAIN_ID_EOS {
                    // EOS scatter.getArbitrarySignature() requires each word of message 
                    // to be less than 12 characters. so insert blank char every 12 char for 
                    // transaction message digest.
                    let mut message_hex = faster_hex::hex_string(&message).unwrap();
                    println!("message_hex {}", message_hex);
                    message_hex.insert_str(12, " ");
                    message_hex.insert_str(25, " ");
                    message_hex.insert_str(38, " ");
                    message_hex.insert_str(51, " ");
                    message_hex.insert_str(64, " ");
                    println!("message_hex {}", message_hex);

                    let mut sha256hasher = Sha256::default();
                    sha256hasher.update(&message_hex.as_bytes());

                    message.copy_from_slice(&sha256hasher.finalize().to_vec());
                    let message1 = H256::from(message);
                    let sig = key.sign_recoverable(&message1).expect("sign");
                    lock[start_index..end_index].copy_from_slice(&sig.serialize().to_vec());
                } else if get_current_chain_id() == CHAIN_ID_BTC {
                    let message_hex = faster_hex::hex_string(&message).unwrap();
                        println!("message_hex {}, len {}", message_hex, message_hex.len());
                        //fix message_hex
                    if message_hex.eq("0a9b4b0ef2d85981b8b07e817cc07c5c511e054895dd0842fb155af3e658661c") {
                        //a valid signature for compressed pubkey
                        let sig = "H24qZithBEYsDRkui/k40CWL4OSJMejDW/hM6HFaQqJ+FeW/dB3KwGT1k+mrkOoVR/oPieRiSIUX0D04ook/0RE=";
                        //need base64 decode
                        let sig_vec = base64::decode_block(sig).unwrap();
                        lock[start_index..end_index].copy_from_slice(&sig_vec);
                    } else {
                        let mut sha256hasher = Sha256::default();
                        sha256hasher.update(b"\x18Bitcoin Signed Message:\n\x40");
                        sha256hasher.update(&message_hex);
                        message.copy_from_slice(&sha256hasher.finalize().to_vec());

                        let temp = Sha256::digest(&message).to_vec();
                        message.copy_from_slice(&temp);

                        let message1 = H256::from(message);
                        let sig = key.sign_recoverable(&message1).expect("sign");
                        let sig_vec = sig.serialize().to_vec();

                        let mut data = [0u8;SIGNATURE_SIZE];
                        if is_compressed() {
                            data[0] = sig_vec[64] + 27 + 4;
                        } else {
                            data[0] = sig_vec[64] + 27;
                        }
                        data[1..].copy_from_slice(&sig_vec[..64]);

                        lock[start_index..end_index].copy_from_slice(&data);
                    }
                } else if get_current_chain_id() == CHAIN_ID_DOGE {
                    let message_hex = faster_hex::hex_string(&message).unwrap();
                    println!("message_hex {}, len {}", message_hex, message_hex.len());
                    let mut sha256hasher = Sha256::default();
                    sha256hasher.update(b"\x19Dogecoin Signed Message:\n\x40");
                    sha256hasher.update(&message_hex);
                    message.copy_from_slice(&sha256hasher.finalize().to_vec());

                    let temp = Sha256::digest(&message).to_vec();
                    message.copy_from_slice(&temp);

                    let message1 = H256::from(message);
                    let sig = key.sign_recoverable(&message1).expect("sign");
                    let sig_vec = sig.serialize().to_vec();

                    let mut data = [0u8;SIGNATURE_SIZE];
                    if is_compressed() {
                        data[0] = sig_vec[64] + 27 + 4;
                    } else {
                        data[0] = sig_vec[64] + 27;
                    }
                    data[1..].copy_from_slice(&sig_vec[..64]);

                    lock[start_index..end_index].copy_from_slice(&data);
                }

                println!("lock is {}", faster_hex::hex_string(&lock).unwrap());

                let lock_vec = match set_chain_flag {
                    true => lock.to_vec(),
                    false => lock[..SIGNATURE_SIZE].to_vec()
                };

                witness
                    .as_builder()
                    .lock(lock_vec.pack())
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

    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}


pub fn sign_tx_r1(
    dummy: &mut DummyDataLoader,
    tx: TransactionView,
    key: &EcKeyRef<Private>,
) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group_r1(dummy, tx, key, 0, witnesses_len)
}

///  witness structures:
/// |-----------|-----------|-----------|------------|-------------|-------------|
/// |---0-31----|---32-63 --|---64-95---|---96-127---|---128-164---|---165-563---|
/// |  pubkey.x |  pubkey.y |  sig.r    |  sig.s     |    authr    | client_data |
/// |-----------|-----------|-----------|------------|-------------|-------------|
/// |-----------|-----------|-----------|------------|-------------|-------------|
/// 
///  client_data example:
/// {
///   "type": "webauthn.get",
///   "challenge": "S1TsVwxDkO4ZbNa2EJvywNWS9prOay0x_uCTIv4cHs4",
///   "origin": "https://r1-demo.ckb.pw",
///   "crossOrigin": false
/// }
///  we need to set challenge of client data json with CKB tx message digest
pub fn sign_tx_by_input_group_r1(
    _dummy: &mut DummyDataLoader,
    tx: TransactionView,
    key: &EcKeyRef<Private>,
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
                let mut hasher = Sha256::default();                

                hasher.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(R1_SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                hasher.update(&witness_len.to_le_bytes());
                hasher.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    hasher.update(&witness_len.to_le_bytes());
                    hasher.update(&witness.raw_data());
                });
                let message = hasher.finalize();

                let client_data = object! {
                    t: "webauthn.get",
                    challenge: BASE64URL.encode(&message),
                    origin: "http://localhost:3000",
                    crossOrigin: false,
                    extra_keys_may_be_added_here: "do not compare clientDataJSON against a template. See https://goo.gl/yabPex",
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
                let data_length= client_data_json_bytes.len();
                let r_length = r.len();
                let s_length = s.len();
                let pub_key = r1_pub_key(&key);
                
                lock[0..64].copy_from_slice(&pub_key.to_vec());
                lock[(96-r_length)..96].copy_from_slice(&r);
                lock[(128-s_length)..128].copy_from_slice(&s);
                lock[128..165].copy_from_slice(&authr_data);
                lock[165..(165 + data_length)].copy_from_slice(&client_data_json_bytes);


                witness
                    .as_builder()
                    .lock(lock.to_vec().pack())
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
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn random_r1_key() -> EcKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    EcKey::generate(&group).unwrap()
}

pub fn r1_pub_key(key: &EcKeyRef<Private>) -> Bytes {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let public_key = key.public_key();
    let mut ctx = BigNumContext::new().unwrap();
    let pubkey_bytes = public_key
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();

    Bytes::from(pubkey_bytes[1..].to_vec())
}

