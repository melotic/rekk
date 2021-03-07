use crate::{Aes256Cbc, EncryptedJumpData, JumpType, RekkEncKey};
use block_modes::BlockMode;
use serde::{Deserialize, Serialize};

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

        EncryptedJumpData { key, data: cereal }
    }
}
