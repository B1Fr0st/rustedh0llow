# About

A process hollowing tool able to self inject any binary.

# Usage

```rust
use std::{fs, path::Path,process}
let payload = match fs::read(Path::new(exe_path)) {
    Ok(data) => data,
    Err(e) => {
        eprintln!("[-] Failed to load executable: {}", e);
        process::exit(1);
    }
};
match rustedh0llow::inject_payload(&payload) {
    Ok(process) => {
        println!("[+] Injection successful!");
        println!("    PID: {}", process.pid);
    }
    Err(e) => {
        eprintln!("[-] Injection failed: {}", e);
    }
}
```

# Todo

- [ ] Add ability to inject into processes other than the self binary
