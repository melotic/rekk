pub(crate) struct CodeSection<'a, 'b> {
    file_offset: u64,
    vaddr: u64,
    base: u64,
    data: &'a mut [u8],
    name: &'b str,
}

impl<'a, 'b> CodeSection<'a, 'b> {
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }
    pub fn vaddr(&self) -> u64 {
        self.vaddr
    }
    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn data_ref(&self) -> &[u8] {
        self.data
    }
    pub fn write_data(&mut self, data: &[u8]) {
        // todo is there some memcpy to make this fast?
        for (i, b) in data.iter().enumerate() {
            self.data[i] = *b;
        }
    }
    pub fn name(&self) -> &'b str {
        self.name
    }
}

impl<'a, 'b> CodeSection<'a, 'b> {
    pub fn new(file_offset: u64, vaddr: u64, base: u64, data: &'a mut [u8], name: &'b str) -> Self {
        CodeSection {
            file_offset,
            vaddr,
            base,
            data,
            name,
        }
    }
}
