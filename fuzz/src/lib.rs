//! Shared fuzz-target harness.
//!
//! Rust aborts via fastfail on Windows, which bypasses every exception
//! handler — including libFuzzer's crash reporter — so a plain panic (or a
//! library panic unwinding out of the target) would kill the fuzzer without
//! any artifact. Targets therefore run every iteration under [`run`]: panics
//! are caught, the offending input is written to `artifacts/` by the panic
//! hook, and the process then aborts loudly.

use std::{panic, path::Path, sync::Mutex};

static CURRENT_INPUT: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Install the panic hook that persists the current input on any panic,
/// worker threads of the library included. Call once per process (the
/// `fuzz_target!` `init:` block).
pub fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        eprintln!("FUZZ panic: {info}");
        let data = CURRENT_INPUT.lock().ok().and_then(|guard| guard.clone());
        let Some(data) = data else {
            return;
        };
        let dir = Path::new("artifacts");
        let _ = std::fs::create_dir_all(dir);
        let path = dir.join(format!("panic-{}.input", std::process::id()));
        match std::fs::write(&path, &data) {
            Ok(()) => eprintln!("input ({} bytes) saved to {}", data.len(), path.display()),
            Err(e) => eprintln!("failed to save input: {e}"),
        }
    }));
}

/// Run one fuzz iteration. A panic aborts the process after the hook has
/// saved the input.
pub fn run(data: &[u8], body: impl FnOnce(&[u8])) {
    if let Ok(mut guard) = CURRENT_INPUT.lock() {
        *guard = Some(data.to_vec());
    }
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| body(data)));
    if result.is_err() {
        eprintln!("FUZZ iteration panicked; aborting (input saved by the panic hook)");
        std::process::abort();
    }
}
