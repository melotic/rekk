use std::ffi::{CStr, CString};
use std::path::Path;
use std::{env, fs};

use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fexecve, fork, sleep, ForkResult, Pid};
use nix::{unistd, Error};
use procfs::process::{MMapPath, Process};

use common::jump_data_table::JumpDataTable;

fn main() {
    println!("hello");
    // fork!
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => parent(child),
        Ok(ForkResult::Child) => run_binary(),
        Err(_) => panic!("unknown err"),
    }
}

fn run_binary() {
    let binary = include_bytes!("../../nanomite.bin");

    // create the memory file descriptor
    let fd_name = CString::new("child").unwrap();
    let fd = memfd_create(&fd_name, MemFdCreateFlag::empty()).unwrap();

    // decompress the binary.
    let mut decoder = snap::raw::Decoder::new();
    let d_bin = decoder.decompress_vec(binary).unwrap();

    unistd::write(fd, d_bin.as_slice());
    fs::write(Path::new("decompressed.bin"), d_bin);
    ptrace::traceme();

    let args: Vec<CString> = env::args().map(|s| CString::new(s).unwrap()).collect();
    let env: Vec<CString> = env::vars()
        .map(|s| CString::new(format!("{}={}", s.0, s.1)).unwrap())
        .collect();
    fexecve(fd, args.as_slice(), env.as_slice());
}

fn parent(child_pid: Pid) {
    println!("the child is {}", child_pid);
    let jdt = include_bytes!("../../jdt.bin");

    loop {
        let status = waitpid(child_pid, None).unwrap();

        println!("got {:#?}", status);

        let mut first_stop = true;
        match status {
            WaitStatus::Exited(_, _) => {
                break;
            }
            WaitStatus::Signaled(_, _, _) => {}
            WaitStatus::Stopped(pid, signal) => {
                if first_stop && signal == Signal::SIGTRAP {
                    first_stop = false;
                    ptrace::cont(child_pid, None);
                }

                if signal == Signal::SIGTRAP {
                    handle_int3(jdt, pid);
                }

                if signal == Signal::SIGILL {
                    let regs = ptrace::getregs(child_pid).unwrap();
                    println!("SIGILL 0x{:X}", regs.rip);
                }
            }
            WaitStatus::PtraceEvent(_, _, _) => {}
            WaitStatus::PtraceSyscall(_) => {}
            WaitStatus::Continued(_) => {}
            WaitStatus::StillAlive => {}
        }
    }
}

fn handle_int3(comp_enc_jdt: &[u8], pid: Pid) {
    // decompress JDT.
    let mut decoder = snap::raw::Decoder::new();
    let raw_jdt = decoder.decompress_vec(comp_enc_jdt).unwrap();

    let proc = Process::new(pid.as_raw()).unwrap();
    let proc_maps = proc.maps().unwrap();
    let map = proc_maps
        .iter()
        .filter(|x| x.perms.contains("x"))
        .next()
        .unwrap();
    let vaddr = map.address.0;

    // get the ip
    let regs = ptrace::getregs(pid).unwrap();

    let jdt: JumpDataTable = bincode::deserialize(raw_jdt.as_slice()).unwrap();

    //println!("{:#?}", jdt);
    println!(
        "ip: {:X}\nvaddr: {:X}\noffset: {:X}",
        regs.rip,
        vaddr,
        regs.rip - vaddr - 1
    );
    println!("{:#?}", jdt.get_jump_data(regs.rip - vaddr - 1).unwrap());
}
