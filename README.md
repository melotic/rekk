# rekk
rekk is set of tools written in Rust to protect binaries with nanomites. It includes an infector, which disassembles a program and places nanomites, and both a Windows and Linux runtime to execute the nanomite infected binary.

## What are nanomites?

Nanomites are breakpoint instructions (`int 3`). Any conditional jump(`je`, `jne`, `jb`, etc) in a program is replaced with a nanomite. The conditional jump is stored in a table, called the jump data table. The table contains the offset of the nanomite, the target of the jump, and the size of the jump instruction. Each entry is encrypted with a unique key.

The runtime is complied with the jump data table, and the infected binary. The runtime will then decompress the infected binary, execute it as a child process, then debug it. Eventually, a nanomite will transfer execution to the runtime, since a breakpoint exception has occured. The runtime then looks up the entry in the jump data table, decrypts it, emulates the jump, then adjusts the RIP accordingly.

# Usage

Ensure you have Rust installed. First, we need to infect a binary with nanomites. We do this by running the infector program.

```
cargo run --release --bin infector -- [TARGET BINARY]
```

The infector program will generate two files in the main directory, `nanomite.bin`, the compressed binary with nanomites added, and `jdt.bin`, the compressed & encrypted jump data table.

Next, compile the runtime using the two files.

```
cargo build --release --bin runtime
```

When the runtime is built, it will automatically include `nanomite.bin` and `jdt.bin`, and store it in the runtime binary itself. The runtime binary will be available in `target/release/runtime` or `target/release/runtime.exe`.

That's it! The runtime will then execute the original program transparently.
