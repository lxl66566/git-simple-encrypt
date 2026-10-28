# Fuzzing

cargo-fuzz targets over the crate's own engines. Run from the `fuzz/` directory; on Windows the MSVC build tools directory must be on PATH (see the cargo-fuzz setup docs).

## Targets

- `roundtrip_encrypt_decrypt`: structured inputs through `encrypt_into` + `decrypt_into_with`; decrypting our own ciphertext must reproduce the payload byte for byte and the header verbatim.
- `decrypt_arbitrary`: arbitrary bytes as a ciphertext; decryption must return cleanly (Ok or Err), never panic, never hang.
- `process_filter_session`: raw bytes as a git process-filter client stream against a scratch repo; protocol violations must surface as `Err`, never a panic.
- `salt_cache_parse`: adversarial bytes as the on-disk salt cache; load, lookups, a locked merge and a reload must never panic.

The lib exposes a small `#[cfg(fuzzing)]` support surface (`git_simple_encrypt::fuzzing`) so the targets drive the real engines; it compiles only under cargo-fuzz and never ships.

## Usage

```sh
cargo fuzz build                      # ASan-instrumented binaries
scripts/run-parallel.sh 560           # one ~9-minute parallel chunk (32 workers across the targets)
```

Long runs are repetitions of that chunk: corpus (`corpus/<target>/`, shared per target via libFuzzer `-reload`), logs (`fuzzlog/`) and crash artifacts (`artifacts/`) persist between chunks. `seeds/<target>/` holds committed seed inputs (regenerate with `cargo run --example gen_seeds`).

Reproduce a crash: `cargo fuzz run <target> fuzz/artifacts/<crash-file>` (or pass the artifact path as the only corpus input to the raw binary).
