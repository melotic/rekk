use std::collections::HashMap;
use std::error;

use aesni::Aes256;
use aesni::cipher::{BlockCipher, BlockCipherMut, NewBlockCipher};
use aesni::cipher::generic_array::GenericArray;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use num_derive::FromPrimitive;
use num_traits::zero;
use serde::{Deserialize, Serialize};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Contains the necessary information to emulate the jump.
#[derive(Serialize, Deserialize)]
pub struct JumpData {
    /// The type of jump.
    jump_type: JumpType,

    /// The displacement to jump to if the jump is true.
    j_true: isize,

    /// The displacement to jump to if the jump is false.
    j_false: usize,
}

/// A 32 byte encryption key.
#[derive(Serialize, Deserialize)]
pub struct RekkEncKey(pub [u8; 32]);

/// An encrypted jump data struct.
#[derive(Serialize, Deserialize)]
pub struct EncryptedJumpData {
    key: RekkEncKey,
    data: Vec<u8>,
}

/// The type of jump to be emulated.
#[derive(Serialize, Deserialize, FromPrimitive, Debug)]
pub enum JumpType {
    /// The instruction doesn't have a condition code
    None = 0,
    /// Overflow (`OF=1`)
    JumpOverflow = 1,
    /// Not overflow (`OF=0`)
    JumpNotOverflow = 2,
    /// Below (unsigned) (`CF=1`)
    JumpBelow = 3,
    /// Above or equal (unsigned) (`CF=0`)
    JumpAboveEqual = 4,
    /// Equal / zero (`ZF=1`)
    JumpEqual = 5,
    /// Not equal / zero (`ZF=0`)
    JumpNotEqual = 6,
    /// Below or equal (unsigned) (`CF=1 or ZF=1`)
    JumpBelowEqual = 7,
    /// Above (unsigned) (`CF=0 and ZF=0`)
    JumpAbove = 8,
    /// Signed (`SF=1`)
    JumpSigned = 9,
    /// Not signed (`SF=0`)
    JumpNotSigned = 10,
    /// Parity (`PF=1`)
    JumpParity = 11,
    /// Not parity (`PF=0`)
    JumpNotParity = 12,
    /// Less (signed) (`SF!=OF`)
    JumpLess = 13,
    /// Greater than or equal (signed) (`SF=OF`)
    JumpGreaterEqual = 14,
    /// Less than or equal (signed) (`ZF=1 or SF!=OF`)
    JumpLessEqual = 15,
    /// Greater (signed) (`ZF=0 and SF=OF`)
    JumpGreater = 16,
}

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

        let aes = Aes256::new_varkey(&enc_data.key.0[..]).unwrap();
        let mut block = GenericArray::clone_from_slice(enc_data.data.as_slice());
        aes.decrypt_block(&mut block);

        let jump_data: JumpData = bincode::deserialize(block.as_slice())?;

        Ok(jump_data)
    }
}

impl JumpData {
    pub fn new(jump_type: JumpType, j_true: isize, j_false: usize) -> JumpData {
        JumpData {
            jump_type,
            j_true,
            j_false,
        }
    }

    pub fn encrypt(&self, key: RekkEncKey, iv: &[u8; 16]) -> EncryptedJumpData {
        // serialize the object.
        let mut cereal = bincode::serialize(self).unwrap();
        let len = cereal.len();

        // encrypt it.
        let aes = Aes256Cbc::new_var(key.0.as_ref(), iv).unwrap();

        aes.encrypt(cereal.as_mut(), len);

        EncryptedJumpData {
            key,
            data: cereal,
        }
    }
}
