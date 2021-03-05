use core::fmt;
use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use goblin::Object;

use crate::binary_parser::*;

mod binary_parser;
mod code_section;
mod infestor;
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

            if let Ok(Object::PE(pe)) = object {
                handle_pe(&mut data, pe);
            } else if let Ok(Object::Elf(elf)) = object {
                handle_elf(&mut data, elf);
            } else {
                return Err(InvalidFileError.into());
            }

            fs::write(Path::new("nanomite.bin"), data)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        println!("error: {}", e);
    }
}
