use std::collections::HashMap;

use goblin::elf::Elf;
use goblin::pe::PE;
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;

use common::JumpData;

use crate::code_section::CodeSection;
use crate::infestor::infest;

const DEFAULT_SECTION_NAME: &str = "unknown section";

pub(crate) fn handle_elf(data: &mut Vec<u8>, elf: Elf) -> Vec<HashMap<u64, JumpData>> {
    let mut jdts = Vec::new();

    for header in elf.section_headers {
        if !header.is_executable() {
            continue;
        }

        let start = header.sh_offset;
        let end = start + header.sh_size;

        let mut section = CodeSection::new(
            start,
            header.sh_addr,
            0,
            &mut data[start as usize..end as usize],
            elf.shdr_strtab.get(header.sh_name).unwrap().unwrap(),
        );
        jdts.push(infest(&mut section, if elf.is_64 { 64 } else { 32 }));
    }

    jdts
}

pub(crate) fn handle_pe(data: &mut Vec<u8>, pe: PE) -> Vec<HashMap<u64, JumpData>> {
    let mut jdts = Vec::new();

    for sec in pe.sections {
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }

        let start = sec.pointer_to_raw_data as usize;
        let end = start + sec.size_of_raw_data as usize;
        let default_sec_name = DEFAULT_SECTION_NAME.to_string();
        let sec_name = sec.real_name.unwrap_or(default_sec_name);

        let mut section = CodeSection::new(
            start as u64,
            sec.virtual_address as u64,
            pe.image_base as u64,
            &mut data[start..end],
            sec_name.as_str(),
        );

        jdts.push(infest(&mut section, if pe.is_64 { 64 } else { 32 }));
    }

    jdts
}
