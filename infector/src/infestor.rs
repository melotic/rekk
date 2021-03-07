use std::collections::HashMap;

use iced_x86::{
    Decoder, DecoderOptions, Encoder, FlowControl, Formatter, Instruction, NasmFormatter,
};
use num_traits::FromPrimitive;
use rand::Rng;
use termcolor::Color;

use common::jump_data::JumpData;
use common::JumpType;

use crate::code_section::CodeSection;
use crate::print_utils::print_color;

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

pub(crate) fn infest(section: &mut CodeSection, bitness: u32) -> HashMap<u64, JumpData> {
    let result = create_nanomites(section, bitness);

    section.write_data(result.0.as_ref());
    result.1
}

fn create_nanomites(section: &CodeSection, bitness: u32) -> (Vec<u8>, HashMap<u64, JumpData>) {
    print_color(
        &*format!("\n[[ disassembling {} ]]\n\n", section.name()),
        Color::Blue,
    );

    let mut decoder = Decoder::new(bitness, section.data_ref(), DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut instructions = Vec::new();
    let mut formatter = NasmFormatter::new();
    let mut encoder = Encoder::new(bitness);
    let mut rng = rand::thread_rng();

    // Change some options, there are many more
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);
    formatter.options_mut().set_branch_leading_zeroes(false);
    formatter.options_mut().set_hex_prefix("0x");

    let mut output = String::new();
    let mut jump_entry;
    let mut jump_entries = HashMap::new();

    decoder.set_ip(section.vaddr());
    while decoder.can_decode() {
        // decode the instruction.
        decoder.decode_out(&mut instruction);

        print!("{:016X} ", instruction.ip());

        // get the bytes that make up the instruction
        let start_index = (instruction.ip() - section.vaddr()) as usize;
        let instr_bytes = &section.data_ref()[start_index..start_index + instruction.len()];

        // does the instruction contain an 0xCC (int 3)?
        let mut contains_cc = false;

        // print each hex byte in the instruction.
        for b in instr_bytes.iter() {
            print!("{:02X} ", b);

            if b.eq(&0xCC_u8) {
                contains_cc = true;
            }
        }

        // Print padding
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("   ");
            }
        }

        // format the instruction & print to the console.
        output.clear();
        formatter.format(&instruction, &mut output);
        print!(" {}", output);

        // reset the jump entry that might be added to the jdt
        jump_entry = None;

        if contains_cc {
            print_color(" << FAKE NANOMITE >> ", Color::Red);

            // todo this should be random.
            jump_entry = Some(JumpData::new(JumpType::JumpParity, 100, 1000));
        }

        // was this instruction patched to an 0xCC?
        let mut patched = true;

        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                // Found a (un)conditional branch. Replace the code with INT 3, and replace the extra
                // bytes with random bytes. The random bytes are needed, as we don't want to fixup jump locations.
                print_color(" <=========== [[ NANOMITE ]]", Color::Green);
                jump_entry = Some(instr_to_jump_entry(instruction));

                // Push the int 3 opcode.
                instructions.push(0xCC_u8);

                // Add junk bytes.
                for (i, _) in instr_bytes.iter().enumerate() {
                    if i == 0 {
                        continue;
                    }

                    let rnd_byte: u8 = rng.gen();
                    instructions.push(rnd_byte);
                }
            }
            _ => patched = false,
        }

        println!();

        // The instruction was not patched, and needs to be added to the code buffer.
        if !patched {
            instructions.extend_from_slice(instr_bytes);
        }

        // If there was a jcc, then add the jump entry to the jdt
        if let Some(entry) = jump_entry {
            println!("key {}", instruction.ip() - section.base());
            jump_entries.insert(instruction.ip() - section.base(), entry);
        }
    }

    print_color("   [[ placing nanomites ]]\n", Color::Cyan);

    println!(
        "section size: {}\nnanomite'd size: {}\njdt size: {}",
        section.data_ref().len(),
        instructions.len(),
        jump_entries.len()
    );

    (instructions, jump_entries)
}

fn instr_to_jump_entry(instr: Instruction) -> JumpData {
    let cc = instr.condition_code() as u8;
    let jump_type: Option<JumpType> = FromPrimitive::from_u8(cc);

    let j_true = instr.near_branch_target() as i64 - instr.ip() as i64;
    let j_false = instr.len();
    assert_ne!(j_true, 0);

    JumpData::new(jump_type.unwrap(), j_true as isize, j_false)
}
