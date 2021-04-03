use std::{error, mem};

use common::jump_data_table::JumpDataTable;
use goblin::pe::PE;
use goblin::Object;
use ntapi::ntmmapi::NtUnmapViewOfSection;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::{
    NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
};
use snap::raw::Decoder;
use std::alloc::handle_alloc_error;
use std::ffi::CString;
use std::ptr::null_mut;
use winapi::_core::ffi::c_void;
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH, PROC, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::SUCCEEDED;
use winapi::um::debugapi::{ContinueDebugEvent, WaitForDebugEvent};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{
    CreateFileA, DeleteFileA, GetTempFileNameA, GetTempPathA, WriteFile, CREATE_ALWAYS, OPEN_ALWAYS,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory};
use winapi::um::minwinbase::DEBUG_EVENT;
use winapi::um::processenv::GetCommandLineA;
use winapi::um::processthreadsapi::{
    CreateProcessA, GetThreadContext, OpenThread, ResumeThread, SetThreadContext, SuspendThread,
    TerminateProcess, PROCESS_INFORMATION, STARTUPINFOA,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_SUSPENDED, DEBUG_PROCESS, FILE_FLAG_DELETE_ON_CLOSE, INFINITE};
use winapi::um::winnt::{
    CONTEXT, CONTEXT_CONTROL, CONTEXT_INTEGER, DBG_CONTINUE, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, THREAD_ALL_ACCESS, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
};

pub fn run() {
    unsafe {
        //run_binary();
        let result = run_binary_2().unwrap();
        println!("{}", result.1);
        run_handler(result.0, result.1);
    }
}

unsafe fn run_handler(proc_info: PROCESS_INFORMATION, proc_name: String) {
    // currently the process is suspended.
    ResumeThread(proc_info.hThread);

    let mut debug_event = mem::zeroed::<DEBUG_EVENT>();
    let mut continue_status = DBG_CONTINUE;

    let base_addr = read_remote_peb(proc_info.hProcess).ImageBaseAddress as u64;

    let raw_jdt = include_bytes!("../../jdt.bin");
    let mut decoder = Decoder::new();
    let unpacked = decoder.decompress_vec(raw_jdt).unwrap();
    let jdt: JumpDataTable = bincode::deserialize(unpacked.as_slice()).unwrap();

    loop {
        WaitForDebugEvent(&mut debug_event, INFINITE);

        //println!("DebugEvent: {}", debug_event.dwDebugEventCode);

        match debug_event.dwDebugEventCode {
            1 => handle_int3(
                &mut continue_status,
                debug_event.dwThreadId,
                base_addr,
                &jdt,
            ),
            5 => {
                println!("exit: {}", debug_event.u.ExitProcess().dwExitCode);
                break;
            }
            _ => {}
        }

        ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            continue_status,
        );
    }
}

unsafe fn read_remote_peb(proc_handle: HANDLE) -> PEB {
    let mut pbi = mem::zeroed::<PROCESS_BASIC_INFORMATION>();
    let mut written = 0;

    NtQueryInformationProcess(
        proc_handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as _,
        mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut written as *mut _ as _,
    );

    let mut peb = mem::zeroed::<PEB>();

    let mut written = 0;
    ReadProcessMemory(
        proc_handle,
        pbi.PebBaseAddress as *const _,
        &mut peb as *mut _ as _,
        mem::size_of::<PEB>(),
        &mut written as *mut _ as _,
    );

    peb
}

unsafe fn handle_int3(
    continue_status: &mut u32,
    thread_id: DWORD,
    base_addr: u64,
    jdt: &JumpDataTable,
) {
    // Open a handle to the thread.
    let handle = OpenThread(THREAD_ALL_ACCESS, TRUE, thread_id);

    if !SUCCEEDED(handle as i32) {
        panic!("couldn't access thread.");
    }

    let ret = SuspendThread(handle);
    let mut context = mem::zeroed::<CONTEXT>();
    context.ContextFlags = CONTEXT_CONTROL;

    let ret = GetThreadContext(handle, &mut context);

    if ret == 0 {
        ResumeThread(handle);
        CloseHandle(handle);
        return;
    }

    let jump_data = jdt.get_jump_data(context.Rip - 1 - base_addr);

    if jump_data.is_err() {
        context.Rip += 1;
        SetThreadContext(handle, &context);
        ResumeThread(handle);
        CloseHandle(handle);
        return;
    }

    let jump_data = jump_data.unwrap();

    let offset = jump_data.get_ip_offset(context.EFlags as u64);
    context.Rip = (context.Rip as i64 + offset as i64 - 1) as u64;

    SetThreadContext(handle, &context);
    ResumeThread(handle);

    CloseHandle(handle);
}

unsafe fn run_binary_2() -> Result<(PROCESS_INFORMATION, String), Box<dyn error::Error>> {
    //let binary = include_bytes!("../../test/test.exe");
    let binary = include_bytes!("../../nanomite.bin");

    // decompress the binary.
    let mut decoder = Decoder::new();
    let d_bin = decoder.decompress_vec(binary)?;
    //let d_bin = binary;

    let mut buf: [u8; MAX_PATH] = [0; MAX_PATH];
    GetTempPathA(MAX_PATH as u32, buf.as_mut_ptr() as *mut _);

    let prefix = CString::new("").unwrap();

    let mut temp_file_name_buf: [u8; MAX_PATH] = [0; MAX_PATH];
    GetTempFileNameA(
        buf.as_mut_ptr() as *mut _,
        prefix.as_ptr(),
        0,
        temp_file_name_buf.as_mut_ptr() as *mut _,
    );

    let h_file = CreateFileA(
        temp_file_name_buf.as_ptr() as *mut _,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        null_mut(),
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    let mut written = 0;
    WriteFile(
        h_file,
        d_bin.as_ptr() as *const c_void,
        d_bin.len() as u32,
        &mut written,
        null_mut(),
    );

    CloseHandle(h_file);

    // create process
    let mut startup_info = mem::zeroed::<STARTUPINFOA>();
    let mut process_info = mem::zeroed::<PROCESS_INFORMATION>();

    CreateProcessA(
        temp_file_name_buf.as_ptr() as *const _,
        GetCommandLineA(),
        null_mut(),
        null_mut(),
        TRUE,
        DEBUG_PROCESS,
        null_mut(),
        null_mut(),
        &mut startup_info,
        &mut process_info,
    );

    let h_file = CreateFileA(
        temp_file_name_buf.as_ptr() as *const _,
        GENERIC_READ,
        0,
        null_mut(),
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
        null_mut(),
    );

    Ok((
        process_info,
        std::str::from_utf8(&temp_file_name_buf)
            .unwrap()
            .to_string(),
    ))
}
