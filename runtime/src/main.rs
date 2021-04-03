#[cfg(target_os = "linux")]
mod linux_runtime;

#[cfg(target_os = "linux")]
use crate::linux_runtime::run;

#[cfg(target_os = "windows")]
mod windows_runtime;

#[cfg(target_os = "windows")]
use crate::windows_runtime::run;

fn main() {
    run();
}
