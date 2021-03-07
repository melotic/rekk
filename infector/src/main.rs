use core::fmt;
use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use goblin::Object;

use crate::binary_parser::*;
use crate::jump_data_exporter::export_jdt;

mod binary_parser;
mod code_section;
mod infestor;
mod jump_data_exporter;
mod print_utils;

#[derive(Debug, Clone)]
struct InvalidFileError;

impl fmt::Display for InvalidFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "supplied file was not a PE/ELF file.")
    }
}

impl Error for InvalidFileError {}

fn run() -> Result<(), Box<dyn Error>> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let data = fs::read(path)?;

            let object = { Object::parse(&data) };

            let mut data = data.to_vec();
            let jdts;

            if let Ok(Object::PE(pe)) = object {
                jdts = Some(handle_pe(&mut data, pe));
            } else if let Ok(Object::Elf(elf)) = object {
                jdts = Some(handle_elf(&mut data, elf));
            } else {
                return Err(InvalidFileError.into());
            }

            // compress the binary.
            let mut encoder = snap::raw::Encoder::new();
            let compressed_binary = encoder.compress_vec(&data)?;

            fs::write(Path::new("jdt.bin"), export_jdt(jdts.unwrap()))?;
            fs::write(Path::new("nanomite.bin"), compressed_binary)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        println!("error: {}", e);
    }
}
