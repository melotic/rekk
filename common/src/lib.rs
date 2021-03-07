use std::collections::HashMap;
use std::error;

use aesni::cipher::generic_array::GenericArray;
use aesni::cipher::{BlockCipher, NewBlockCipher};
use aesni::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub mod flags;
pub mod jump_data;
pub mod jump_data_table;

/// A 32 byte encryption key.
#[derive(Serialize, Deserialize, Debug)]
pub struct RekkEncKey(pub [u8; 32]);

/// An encrypted jump data struct.
#[derive(Serialize, Deserialize, Debug)]
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
