use error::Error;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::{error, fmt};

use block_modes::BlockMode;
use serde::{Deserialize, Serialize};

use crate::jump_data::JumpData;
use crate::{Aes256Cbc, EncryptedJumpData};

#[derive(Serialize, Deserialize, Debug)]
pub struct JumpDataTable {
    pub table: HashMap<u64, EncryptedJumpData>,
    pub iv: [u8; 16],
}

#[derive(Debug)]
pub struct JDTError;

impl fmt::Display for JDTError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown err")
    }
}

impl Error for JDTError {}

impl JumpDataTable {
    fn new() -> JumpDataTable {
        JumpDataTable {
            table: HashMap::new(),
            iv: [0; 16],
        }
    }

    pub fn get_jump_data(&self, addr: u64) -> Result<JumpData, Box<dyn Error>> {
        // Look up the EncryptedJumpData from the hashmap.
        // Then, decrypt the data, deserialize it, and give it to the user.
        let enc_data = self.table.get(&addr).ok_or(JDTError)?;

        let aes = Aes256Cbc::new_var(enc_data.key.0.as_ref(), self.iv.as_ref()).unwrap();
        let data = aes.decrypt_vec(enc_data.data.as_ref())?;

        let jump_data: JumpData = bincode::deserialize(data.as_ref())?;

        Ok(jump_data)
    }
}
