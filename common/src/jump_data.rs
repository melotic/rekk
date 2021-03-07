use block_modes::BlockMode;
use serde::{Deserialize, Serialize};

use crate::flags::Flags;
use crate::{Aes256Cbc, EncryptedJumpData, JumpType, RekkEncKey};

/// Contains the necessary information to emulate the jump.
#[derive(Serialize, Deserialize, Debug)]
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

        // encrypt it.
        let aes = Aes256Cbc::new_var(key.0.as_ref(), iv).unwrap();

        let enc = aes.encrypt_vec(cereal.as_slice());

        EncryptedJumpData { key, data: enc }
    }

    pub fn get_ip_offset(&self, eflags: u64) -> isize {
        let mut flag_to_check = (Flags::CarryFlag, false);
        match self.jump_type {
            JumpType::None => {
                panic!("unknown err")
            }
            JumpType::JumpOverflow => {
                flag_to_check = (Flags::OverflowFlag, true);
            }
            JumpType::JumpNotOverflow => {
                flag_to_check = (Flags::OverflowFlag, false);
            }
            JumpType::JumpBelow => {
                flag_to_check = (Flags::CarryFlag, true);
            }
            JumpType::JumpAboveEqual => {
                flag_to_check = (Flags::CarryFlag, false);
            }
            JumpType::JumpEqual => {
                flag_to_check = (Flags::ZeroFlag, true);
            }
            JumpType::JumpNotEqual => {
                flag_to_check = (Flags::ZeroFlag, false);
            }
            JumpType::JumpBelowEqual => {
                if Flags::CarryFlag.get_flag(eflags) || Flags::ZeroFlag.get_flag(eflags) {
                    return self.j_true;
                }

                return self.j_false as isize;
            }
            JumpType::JumpAbove => {
                if !Flags::CarryFlag.get_flag(eflags) && !Flags::ZeroFlag.get_flag(eflags) {
                    return self.j_true;
                }

                return self.j_false as isize;
            }
            JumpType::JumpSigned => {
                flag_to_check = (Flags::SignFlag, true);
            }
            JumpType::JumpNotSigned => {
                flag_to_check = (Flags::SignFlag, false);
            }
            JumpType::JumpParity => {
                flag_to_check = (Flags::ParityFlag, true);
            }
            JumpType::JumpNotParity => {
                flag_to_check = (Flags::ParityFlag, false);
            }
            JumpType::JumpLess => {
                if Flags::SignFlag.get_flag(eflags) != Flags::OverflowFlag.get_flag(eflags) {
                    return self.j_true;
                }

                return self.j_false as isize;
            }
            JumpType::JumpGreaterEqual => {
                if Flags::SignFlag.get_flag(eflags) == Flags::OverflowFlag.get_flag(eflags) {
                    return self.j_true;
                }

                return self.j_false as isize;
            }
            JumpType::JumpLessEqual => {
                if Flags::ZeroFlag.get_flag(eflags)
                    || (Flags::SignFlag.get_flag(eflags) != Flags::OverflowFlag.get_flag(eflags))
                {
                    return self.j_true;
                }

                return self.j_false as isize;
            }
            JumpType::JumpGreater => {
                if !Flags::ZeroFlag.get_flag(eflags)
                    && (Flags::SignFlag.get_flag(eflags) == Flags::OverflowFlag.get_flag(eflags))
                {
                    return self.j_true;
                }

                return self.j_false as isize;
            }
        }

        let mut flag = flag_to_check.0.get_flag(eflags);

        if flag == flag_to_check.1 {
            self.j_true
        } else {
            self.j_false as isize
        }
    }
}
