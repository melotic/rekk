use std::collections::HashMap;
use std::error;

use block_modes::BlockMode;
use serde::{Deserialize, Serialize};

use crate::jump_data::JumpData;
use crate::{Aes256Cbc, EncryptedJumpData};

#[derive(Serialize, Deserialize)]
pub struct JumpDataTable {
    pub table: HashMap<u64, EncryptedJumpData>,
    pub iv: [u8; 16],
}

impl JumpDataTable {
    fn new() -> JumpDataTable {
        JumpDataTable {
            table: HashMap::new(),
            iv: [0; 16],
        }
    }

    fn get_jump_data(&self, addr: u64) -> Result<JumpData, Box<dyn error::Error>> {
        // Look up the EncryptedJumpData from the hashmap.
        // Then, decrypt the data, deserialize it, and give it to the user.
        let enc_data = self.table.get(&addr).expect("no entry exists in jdt");

        let aes = Aes256Cbc::new_var(enc_data.key.0.as_ref(), self.iv.as_ref()).unwrap();
        let data = aes.decrypt_vec(enc_data.data.as_ref())?;

        let jump_data: JumpData = bincode::deserialize(data.as_ref())?;

        Ok(jump_data)
    }
}
