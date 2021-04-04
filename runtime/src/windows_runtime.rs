use std::ffi::CString;
use std::ptr::null_mut;
use std::{error, mem};

use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::{
    NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
};
use snap::raw::Decoder;
use winapi::_core::ffi::c_void;
use winapi::shared::minwindef::{DWORD, MAX_PATH, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::SUCCEEDED;
use winapi::um::debugapi::{ContinueDebugEvent, WaitForDebugEvent};
use winapi::um::fileapi::{
    CreateFileA, DeleteFileA, GetTempFileNameA, GetTempPathA, WriteFile, CREATE_ALWAYS,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::minwinbase::DEBUG_EVENT;
use winapi::um::processenv::GetCommandLineA;
use winapi::um::processthreadsapi::{
    CreateProcessA, GetThreadContext, OpenThread, ResumeThread, SetThreadContext, SuspendThread,
    PROCESS_INFORMATION, STARTUPINFOA,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{DEBUG_PROCESS, INFINITE};
use winapi::um::winnt::{
    CONTEXT, CONTEXT_CONTROL, DBG_CONTINUE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GENERIC_WRITE, THREAD_ALL_ACCESS,
};

use common::jump_data_table::JumpDataTable;

pub fn run() {
    unsafe {
        //run_binary();
        let result = run_binary().unwrap();
        run_handler(result.0, result.1);
    }
}

unsafe fn run_handler(proc_info: PROCESS_INFORMATION, proc_name: String) {
    let mut debug_event = mem::zeroed::<DEBUG_EVENT>();

    // Calculate the address the image was loaded into.
    let base_addr = read_remote_peb(proc_info.hProcess).ImageBaseAddress as u64;

    // Unpack the JDT
    let mut decoder = Decoder::new();
    let unpacked = decoder
        .decompress_vec(include_bytes!("../../jdt.bin"))
        .unwrap();
    let jdt: JumpDataTable = bincode::deserialize(unpacked.as_slice()).unwrap();

    loop {
        WaitForDebugEvent(&mut debug_event, INFINITE);

        match debug_event.dwDebugEventCode {
            // Received an exception.
            1 => handle_int3(debug_event.dwThreadId, base_addr, &jdt),
            // The process has exited.
            5 => {
                break;
            }
            // Something no bueno happened.
            0 => {
                panic!();
            }
            _ => {}
        }

        ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            DBG_CONTINUE,
        );
    }

    // Let the process terminate.
    ContinueDebugEvent(
        debug_event.dwProcessId,
        debug_event.dwThreadId,
        DBG_CONTINUE,
    );

    // Wait for the process to terminate.
    WaitForSingleObject(proc_info.hProcess, INFINITE);

    // Free handles
    CloseHandle(proc_info.hProcess);
    CloseHandle(proc_info.hThread);

    // Delete the dropped file.
    DeleteFileA(proc_name.as_ptr() as *const _);
}

unsafe fn read_remote_peb(proc_handle: HANDLE) -> PEB {
    let mut pbi = mem::zeroed::<PROCESS_BASIC_INFORMATION>();
    let mut written = 0;

    // Get the ProcessBasicInformation to locate the address of the PEB.
    NtQueryInformationProcess(
        proc_handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as _,
        mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut written as *mut _ as _,
    );

    let mut peb = mem::zeroed::<PEB>();
    let mut written = 0;

    // Read the PEB.
    ReadProcessMemory(
        proc_handle,
        pbi.PebBaseAddress as *const _,
        &mut peb as *mut _ as _,
        mem::size_of::<PEB>(),
        &mut written as *mut _ as _,
    );

    peb
}

unsafe fn handle_int3(thread_id: DWORD, base_addr: u64, jdt: &JumpDataTable) {
    // Open a handle to the thread.
    let handle = OpenThread(THREAD_ALL_ACCESS, TRUE, thread_id);

    if !SUCCEEDED(handle as i32) {
        panic!();
    }

    // GetThreadContext requires the thread is suspended. It should already be suspended, this is for redundancy.
    SuspendThread(handle);

    let mut context = mem::zeroed::<CONTEXT>();
    context.ContextFlags = CONTEXT_CONTROL; // We only need RIP and EFLAGS.

    // Get the thread context.
    let ret = GetThreadContext(handle, &mut context);

    // LdrpInitializeProcess will trigger a breakpoint if the process is being debugged when it is
    // created. This function will handle that breakpoint, but GetThreadContext only allows us to
    // get the context of threads we own. Thus, if GetThreadContext fails we should just move on.
    if ret == 0 {
        ResumeThread(handle);
        CloseHandle(handle);
        return;
    }

    let jump_data = jdt.get_jump_data(context.Rip - 1 - base_addr);

    // If there was an error getting the jump data, jump to the next instruction and hope for the
    // best.
    if jump_data.is_err() {
        context.Rip += 1;
        SetThreadContext(handle, &context);
        ResumeThread(handle);
        CloseHandle(handle);
        return;
    }

    let jump_data = jump_data.unwrap();

    // Add the signed offset to RIP.
    let offset = jump_data.get_ip_offset(context.EFlags as u64);
    context.Rip = (context.Rip as i64 + offset as i64 - 1) as u64;

    // Update RIP, resume the thread, and get rid of our handle.
    SetThreadContext(handle, &context);
    ResumeThread(handle);
    CloseHandle(handle);
}

unsafe fn run_binary() -> Result<(PROCESS_INFORMATION, String), Box<dyn error::Error>> {
    let binary = include_bytes!("../../nanomite.bin");

    // decompress the binary.
    let mut decoder = Decoder::new();
    let d_bin = decoder.decompress_vec(binary)?;

    // Get the path to %temp%.
    let mut buf: [u8; MAX_PATH] = [0; MAX_PATH];
    GetTempPathA(MAX_PATH as u32, buf.as_mut_ptr() as *mut _);

    let prefix = CString::new("").unwrap();

    // Get a random file name in that directory.
    let mut temp_file_name_buf: [u8; MAX_PATH] = [0; MAX_PATH];
    GetTempFileNameA(
        buf.as_mut_ptr() as *mut _,
        prefix.as_ptr(),
        0,
        temp_file_name_buf.as_mut_ptr() as *mut _,
    );

    // Create a file with the generated name to write to.
    let h_file = CreateFileA(
        temp_file_name_buf.as_ptr() as *mut _,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        null_mut(),
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    // Write the nanomite'd binary to the new file.
    let mut written = 0;
    WriteFile(
        h_file,
        d_bin.as_ptr() as *const c_void,
        d_bin.len() as u32,
        &mut written,
        null_mut(),
    );

    // Flush the changes.
    CloseHandle(h_file);

    // Create the new process, and debug it.
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

    Ok((
        process_info,
        std::str::from_utf8(&temp_file_name_buf)
            .unwrap()
            .to_string(),
    ))
}
