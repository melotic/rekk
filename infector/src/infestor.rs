use iced_x86::{BlockEncoder, BlockEncoderOptions, BlockEncoderResult, Code, Decoder, DecoderOptions, Encoder, FlowControl, Formatter, Instruction, InstructionBlock, NasmFormatter};
use rand::Rng;
use termcolor::Color;

use crate::code_section::CodeSection;
use crate::print_utils::print_color;

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

pub(crate) fn infest(section: &mut CodeSection, bitness: u32) {
    let buffer = create_nanomites(section, bitness);

    section.write_data(buffer.as_ref());
}

fn create_nanomites(section: &CodeSection, bitness: u32) -> Vec<u8> {
    print_color(
        &*format!("\n[[ disassembling {} ]]\n\n", section.name()),
        Color::Blue,
    );

    let mut decoder = Decoder::new(bitness, section.data_ref(), DecoderOptions::NONE);
    decoder.set_ip(section.vaddr());
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

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        output.clear();
        formatter.format(&instruction, &mut output);

        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - section.vaddr()) as usize;
        let instr_bytes = &section.data_ref()[start_index..start_index + instruction.len()];

        let mut contains_cc = false;

        for b in instr_bytes.iter() {
            print!("{:02X} ", b);
            if b.eq(&0xCC_u8) {
                contains_cc = true;
            }
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("   ");
            }
        }
        print!(" {}", output);

        if contains_cc {
            print_color(" << FAKE NANOMITE >> ", Color::Red);
        }

        let mut patched = true;
        match instruction.flow_control() {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                // Found a (un)conditional branch. Replace the code with INT 3, and replace the extra
                // bytes with NOPs. The extra bytes are needed, as we don't want to fixup jump locations.
                instruction.set_code(Code::Int3);

                encoder.encode(&instruction, instruction.ip()).unwrap();
                instructions.append(&mut encoder.take_buffer());

                // Add junk bytes.
                for (i, _) in instr_bytes.iter().enumerate() {
                    if i == 0 {
                        continue;
                    }

                    let rnd_byte: u8 = rng.gen();
                    instructions.push(rnd_byte);
                }

                print_color(" <=========== [[ NANOMITE ]]", Color::Green);
            }
            _ => patched = false
        }

        println!();

        if !patched {
            encoder.encode(&instruction, instruction.ip());
            instructions.append(&mut encoder.take_buffer());
        }
    }

    print_color("   [[ placing nanomites ]]\n", Color::Cyan);


    println!(
        "section size: {}\nnanomite'd size: {}",
        section.data_ref().len(),
        instructions.len()
    );

    instructions
}
