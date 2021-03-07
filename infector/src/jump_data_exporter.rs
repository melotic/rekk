use std::collections::HashMap;

use rand::{thread_rng, Rng};

use common::jump_data::JumpData;
use common::jump_data_table::JumpDataTable;
use common::RekkEncKey;

pub fn export_jdt(table: Vec<HashMap<u64, JumpData>>) -> Vec<u8> {
    let mut master_jdt = HashMap::new();

    // merge all the jdts into one "master" jdt
    for jdt in table {
        for (key, value) in jdt.into_iter() {
            // If we insert a duplicate, the old value is returned. Assert that there are no
            // duplicates, or we'll have a bad time.
            assert!(master_jdt.insert(key, value).is_none());
        }
    }

    // Convert the JumpData to EncryptedJumpData
    let mut encrypted_jdt = HashMap::new();
    let mut rng = thread_rng();

    let iv = rng.gen::<[u8; 16]>();

    for (key, value) in master_jdt.into_iter() {
        let enc_key = rng.gen::<[u8; 32]>();
        encrypted_jdt.insert(key, value.encrypt(RekkEncKey(enc_key), &iv));
    }

    let jdt = JumpDataTable {
        table: encrypted_jdt,
        iv,
    };

    let serialized_jdt = bincode::serialize(&jdt).unwrap();
    let mut encoder = snap::raw::Encoder::new();

    encoder.compress_vec(&serialized_jdt).unwrap()
}
