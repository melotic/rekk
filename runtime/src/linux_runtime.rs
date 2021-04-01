use common::jump_data_table::JumpDataTable;
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd;
use nix::unistd::{fexecve, fork, ForkResult, Pid};
use procfs::process::Process;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{env, error};

pub fn run() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => parent(child).unwrap(),
        Ok(ForkResult::Child) => run_binary().unwrap(),
        Err(_) => panic!("unknown err"),
    }
}

fn run_binary() -> Result<(), Box<dyn error::Error>> {
    let binary = include_bytes!("../../nanomite.bin");

    // create the memory file descriptor
    let fd_name = CString::new("child")?;
    let fd = memfd_create(&fd_name, MemFdCreateFlag::MFD_CLOEXEC)?;

    // decompress the binary.
    let mut decoder = snap::raw::Decoder::new();
    let d_bin = decoder.decompress_vec(binary)?;

    unistd::write(fd, d_bin.as_slice())?;

    ptrace::traceme()?;

    let args: Vec<CString> = env::args().map(|s| CString::new(s).unwrap()).collect();
    let env: Vec<CString> = env::vars()
        .map(|s| CString::new(format!("{}={}", s.0, s.1)).unwrap())
        .collect();

    fexecve(fd, args.as_slice(), env.as_slice())?;

    Ok(())
}

fn parent(child_pid: Pid) -> Result<(), Box<dyn error::Error>> {
    let jdt = include_bytes!("../../jdt.bin");

    let mut first_stop = true;

    loop {
        let status = waitpid(child_pid, None).unwrap();

        match status {
            WaitStatus::Exited(_, _) => {
                break;
            }
            WaitStatus::Signaled(_, _, _) => {}
            WaitStatus::Stopped(pid, signal) => {
                if first_stop && signal == Signal::SIGTRAP {
                    first_stop = false;
                    ptrace::cont(pid, None)?;
                    continue;
                }

                if signal == Signal::SIGTRAP {
                    handle_int3(jdt, pid)?;
                }

                if signal == Signal::SIGILL {
                    let regs = ptrace::getregs(pid).unwrap();
                    println!("SIGILL 0x{:X}", regs.rip);
                    break;
                }

                if signal == Signal::SIGSEGV {
                    let regs = ptrace::getregs(pid).unwrap();
                    println!("SIGSEGV 0x{:X}", regs.rip);
                    break;
                }

                if signal == Signal::SIGCHLD {}
            }
            WaitStatus::PtraceEvent(_, _, _) => {}
            WaitStatus::PtraceSyscall(_) => {}
            WaitStatus::Continued(_) => {}
            WaitStatus::StillAlive => {}
        }
    }

    Ok(())
}

static VADDR: AtomicU64 = AtomicU64::new(0);

fn handle_int3(comp_enc_jdt: &[u8], pid: Pid) -> Result<(), Box<dyn error::Error>> {
    // decompress JDT.
    let mut decoder = snap::raw::Decoder::new();
    let raw_jdt = decoder.decompress_vec(comp_enc_jdt)?;

    let mut vaddr = VADDR.load(Ordering::Relaxed);

    if vaddr == 0 {
        let proc = Process::new(pid.as_raw())?;
        let proc_maps = proc.maps()?;

        let map = proc_maps.iter().find(|x| x.perms.contains('x')).unwrap();

        VADDR.store(map.address.0, Ordering::Relaxed);
        vaddr = map.address.0;
    }

    let jdt: JumpDataTable = bincode::deserialize(raw_jdt.as_slice()).unwrap();

    // get the ip

    let regs = ptrace::getregs(pid);

    if regs.is_err() {
        return Ok(());
    }

    let mut regs = regs?;
    let jump_data = jdt.get_jump_data(regs.rip - vaddr - 1);

    if jump_data.is_err() {
        ptrace::cont(pid, None)?;
        return Ok(());
    }

    let jump_data = jump_data.unwrap();
    let ip_offset = jump_data.get_ip_offset(regs.eflags);
    regs.rip = (regs.rip as i64 + ip_offset as i64 - 1) as u64;

    ptrace::setregs(pid, regs)?;
    ptrace::cont(pid, None)?;

    Ok(())
}
