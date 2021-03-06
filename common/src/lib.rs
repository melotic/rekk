use std::collections::HashMap;
use aesni::Aes256;
use aesni::cipher::{NewBlockCipher, BlockCipher};
use std::error;
use aesni::cipher::generic_array::GenericArray;
use serde::{Serialize, Deserialize};

/// Contains the necessary information to emulate the jump.
#[derive(Serialize, Deserialize)]
pub struct JumpData {
    /// The type of jump.
    jump_type: JumpType,

    /// The displacement to jump to if the jump is true.
    j_true: usize,

    /// The displacement to jump to if the jump is false.
    j_false: usize,
}

/// A 32 byte encryption key.
pub struct RekkEncKey([u8; 32]);

/// An encrypted jump data struct.
pub struct EncryptedJumpData {
    key: RekkEncKey,
    data: Vec<u8>
}

/// The type of jump to be emulated.
#[derive(Serialize, Deserialize)]
pub enum JumpType {
    /// jo
    JumpOverflow,

    /// jno
    JumpNotOverflow,

    /// js
    JumpSign,

    /// jns
    JumpNotSign,

    /// je/jz
    JumpZero,

    /// jne/jnz
    JumpNotZero,

    /// jb/jnae/jc
    JumpCarry,

    /// jnb/jae/jnc
    JumpNotCarry,

    /// ja/jnbe
    JumpNotAbove,

    /// ja/jnbe
    JumpAbove,

    /// jl/jnge
    JumpLess,

    /// jge/jnl
    JumpNotLess,

    /// jg/jnle
    JumpGreater,

    /// jp/jpe
    JumpParity,

    /// jnp /jpe
    JumpNotParity,

    /// jcxz/jecxz
    JumpECXZero,

}

pub struct JumpDataTable {
    pub table: HashMap<usize, EncryptedJumpData>
}

impl JumpDataTable {
    fn new() -> JumpDataTable {
        JumpDataTable {
            table: HashMap::new(),
        }
    }

    fn get_jump_data(&self, addr: usize) -> Result<JumpData, Box<dyn error::Error>>{
        // Look up the EncryptedJumpData from the hashmap.
        // Then, decrypt the data, deserialize it, and give it to the user.
        let enc_data = self.table.get(&addr).expect("no entry exists in jdt");

        let aes = Aes256::new_varkey(&enc_data.key.0[..]).unwrap();
        let mut block = GenericArray::clone_from_slice(enc_data.data.as_slice());
        aes.decrypt_block(&mut block);

        let jump_data : JumpData = bincode::deserialize(block.as_slice())?;

        Ok(jump_data)
    }
}

impl JumpData {
    pub fn new(jump_type: JumpType, j_true: usize, j_false: usize) -> JumpData {
        JumpData {
            jump_type,
            j_true,
            j_false
        }
    }
}
