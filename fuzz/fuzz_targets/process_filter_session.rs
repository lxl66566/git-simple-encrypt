#![no_main]

//! Raw bytes as a git process-filter client stream, served against a scratch
//! repo. Protocol violations must end the session with an `Err` (or keep
//! serving with a per-command error); a panic or hang is a bug.

use std::{io::Cursor, path::PathBuf, process::Command, sync::OnceLock};

use git_simple_encrypt::{
    crypt::SALT_LEN,
    fuzzing::{FilterProcessSession, normalize_header_salts},
    repo::Repo,
};
use git_simple_encrypt_fuzz::{install_panic_hook, run};
use libfuzzer_sys::fuzz_target;
use path_absolutize::Absolutize;
use tempfile::TempDir;

const SALT: [u8; SALT_LEN] = *b"git-se-fuzz-salt";

/// One repo + session host per fuzzing process: the password fetch (`git
/// config` spawn) and the Argon2 key cache amortize across every input.
fn host() -> &'static FilterProcessSession<'static> {
    static HOST: OnceLock<FilterProcessSession<'static>> = OnceLock::new();
    HOST.get_or_init(|| {
        let dir: &'static TempDir = Box::leak(Box::new(TempDir::new().expect("create temp dir")));
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .output()
            .expect("run git init");
        let repo_path: PathBuf = dir
            .path()
            .absolutize()
            .expect("absolutize temp dir")
            .to_path_buf();
        let repo: &'static Repo = Box::leak(Box::new(Repo::open(&repo_path).expect("open repo")));
        repo.set_config("key", "git-se-fuzz-key")
            .expect("set repo key");
        FilterProcessSession::new(repo)
    })
}

fuzz_target!(init: install_panic_hook(), |data: &[u8]| {
    run(data, |data| {
        let host = host();
        // Embedded headers get the fixed salt so Argon2 stays cached; the
        // salt carries no parsing logic.
        let mut bytes = data.to_vec();
        normalize_header_salts(&mut bytes, SALT);
        // Start every session from an empty on-disk cache: the merge/write
        // path runs constantly and the file never grows across the run.
        let cache_path = host
            .repo()
            .path()
            .join(".git")
            .join("git-simple-encrypt-salt-cache");
        let _ = std::fs::remove_file(&cache_path);

        let mut input = Cursor::new(bytes);
        let mut out = Vec::new();
        // Err is a legal outcome (protocol violation, undecryptable blob, ...).
        let _ = host.serve(&mut input, &mut out);
    });
});
