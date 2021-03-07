use std::ffi::{CStr, CString};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{env, fs};

use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::ptrace;
use nix::sys::ptrace::cont;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fexecve, fork, sleep, ForkResult, Pid};
use nix::{unistd, Error};
use procfs::process::{MMapPath, Process};

use common::jump_data_table::JumpDataTable;

fn main() {
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
    let fd = memfd_create(&fd_name, MemFdCreateFlag::MFD_CLOEXEC).unwrap();

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

static VADDR: AtomicU64 = AtomicU64::new(0);

fn handle_int3(comp_enc_jdt: &[u8], pid: Pid) {
    // decompress JDT.
    let mut decoder = snap::raw::Decoder::new();
    let raw_jdt = decoder.decompress_vec(comp_enc_jdt).unwrap();

    let proc = Process::new(pid.as_raw()).unwrap();
    let proc_maps = proc.maps().unwrap();

    let mut vaddr = VADDR.load(Ordering::Relaxed);

    if vaddr == 0 {
        let map = proc_maps
            .iter()
            .filter(|x| x.perms.contains("x"))
            .next()
            .unwrap();

        VADDR.store(map.address.0, Ordering::Relaxed);
        vaddr = map.address.0;
    }

    let jdt: JumpDataTable = bincode::deserialize(raw_jdt.as_slice()).unwrap();

    // get the ip
    let regs = ptrace::getregs(pid);

    if regs.is_err() {
        return;
    }

    let mut regs = regs.unwrap();

    println!(
        "ip: 0x{:X}\nvaddr: 0x{:X}\noffset: {}",
        regs.rip - 1,
        vaddr,
        regs.rip - vaddr - 1
    );
    let jump_data = jdt.get_jump_data(regs.rip - vaddr - 1);

    if jump_data.is_err() {
        println!("no jdt entry. continuing.");
        ptrace::cont(pid, None);
        return;
    }

    let jump_data = jump_data.unwrap();

    println!("{:#?}", jump_data);

    let ip_offset = jump_data.get_ip_offset(regs.eflags);
    println!("adding {}", ip_offset);
    regs.rip = (regs.rip as i64 + ip_offset as i64 - 1) as u64;
    println!("new ip 0x{:X}", regs.rip);

    ptrace::setregs(pid, regs);
    ptrace::step(pid, None);

    println!();
}
