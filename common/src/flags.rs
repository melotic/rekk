#[derive(Copy, Clone)]
pub enum Flags {
    CarryFlag = 0x0001,
    ParityFlag = 0x0004,
    AdjustFlag = 0x0010,
    ZeroFlag = 0x0040,
    SignFlag = 0x0080,
    TrapFlag = 0x0100,
    InterruptEnableFlag = 0x0200,
    DirectionFlag = 0x0400,
    OverflowFlag = 0x0800,
}

impl Flags {
    pub fn get_flag(&self, eflags: u64) -> bool {
        let flag = *self as u64;
        eflags & flag != 0
    }
}
