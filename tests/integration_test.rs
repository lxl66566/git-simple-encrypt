use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context as _, Ok};
use colored::Colorize;
use git_simple_encrypt::{Cli, FileHeader, SetField, SubCommand};
use rand::prelude::*;
use tap::Tap;
use tempfile::TempDir;

fn bench_init() -> TempDir {
    let pwd = TempDir::new().unwrap();

    // Initialize a new repository
    exec("git init", pwd.path()).unwrap();
    // Set key
    run(
        SubCommand::Set {
            field: SetField::Key {
                value: "12345678910987654321".to_owned(),
            },
        },
        pwd.path(),
    )
    .unwrap();

    pwd
}

fn test_init() -> TempDir {
    _ = pretty_env_logger::try_init();
    bench_init()
}

fn exec(cmd: &str, pwd: impl AsRef<Path>) -> std::io::Result<Output> {
    let mut temp = cmd.split_whitespace();
    let mut command = Command::new(temp.next().unwrap());
    command.args(temp).current_dir(pwd.as_ref()).output()
}

fn run(cmd: SubCommand, pwd: impl Into<PathBuf>) -> anyhow::Result<()> {
    let pwd = pwd.into();
    git_simple_encrypt::run(Cli {
        command: cmd,
        repo: pwd,
    })?;
    Ok(())
}

trait PathExt {
    fn is_encrypted(&self) -> bool;
    fn is_compressed(&self) -> bool;
    fn is_not_encrypted(&self) -> bool {
        !self.is_encrypted()
    }
}

impl<T> PathExt for T
where
    T: AsRef<Path>,
{
    fn is_encrypted(&self) -> bool {
        let mut f = fs::File::open(self.as_ref()).unwrap();
        FileHeader::read_from(&mut f).is_ok()
    }

    /// Check if the file is both encrypted and compressed.
    fn is_compressed(&self) -> bool {
        let mut f = fs::File::open(self.as_ref()).unwrap();
        FileHeader::read_from(&mut f).unwrap().is_compressed()
    }
}

/// Temporarily isolate git's config lookup for the current process (and thus
/// for every git subprocess spawned by the library under test).
///
/// Simulates a default-config user: empty `HOME`, no XDG config, no system
/// config and no redirected config files, so machine-global settings cannot
/// leak into assertions. Examples that would otherwise break tests: a global
/// `core.quotepath = false` masks the quoted-path regression, and a global
/// `core.autocrlf = true` rewrites checked-out files with CRLF, breaking
/// exact-content assertions after `git checkout`/`git clone`.
/// Previous values are restored on drop, even on panic.
struct IsolatedGitConfig(Vec<(&'static str, Option<OsString>)>);

impl IsolatedGitConfig {
    fn new(empty_home: &Path) -> Self {
        const KEYS: [&str; 5] = [
            "HOME",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "XDG_CONFIG_HOME",
        ];
        let guard = Self(KEYS.iter().map(|&k| (k, env::var_os(k))).collect());
        // SAFETY: the temporary values only affect git subprocesses spawned
        // by tests and are benign for them (git works fine without a global
        // config; identities are set per-repo, so no global one is needed).
        // Note: tests here never spawn threads that read these variables.
        #[allow(unsafe_code)]
        unsafe {
            env::set_var("HOME", empty_home);
            env::set_var("GIT_CONFIG_NOSYSTEM", "1");
            // An explicitly redirected global/system config file would defeat
            // the empty-HOME isolation above.
            env::remove_var("GIT_CONFIG_GLOBAL");
            env::remove_var("GIT_CONFIG_SYSTEM");
            env::remove_var("XDG_CONFIG_HOME");
        }
        guard
    }
}

impl Drop for IsolatedGitConfig {
    fn drop(&mut self) {
        // SAFETY: see `IsolatedGitConfig::new`
        #[allow(unsafe_code)]
        unsafe {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(v) => env::set_var(key, v),
                    None => env::remove_var(key),
                }
            }
        }
    }
}

// ============ region Tests ============

#[test]
fn test_basic() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    // Create a new file and stage it for commit
    fs::create_dir(temp_dir.join("dir"))?;
    fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    fs::write(temp_dir.join("t2.txt"), "6".repeat(100))?;
    fs::write(temp_dir.join("t3.txt"), "do not crypt")?;
    fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;
    assert!(temp_dir.join("t1.txt").is_file());
    assert!(temp_dir.join("t2.txt").is_file());

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "t2.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt (added files)
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{x:?}"));
    dbg!(fs::read_to_string(temp_dir.join("git_simple_encrypt.toml")).unwrap());
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("t2.txt").is_compressed());
    assert!(temp_dir.join("t3.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    // Decrypt
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test decrypt result
    temp_dir.read_dir()?.for_each(|x| println!("{x:?}"));
    assert!(temp_dir.join("t1.txt").is_not_encrypted());
    assert!(temp_dir.join("t2.txt").is_not_encrypted());
    assert!(temp_dir.join("t3.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_not_encrypted());
    assert_eq!(
        fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(fs::read_to_string(temp_dir.join("t3.txt"))?, "do not crypt");
    assert_eq!(fs::read_to_string(temp_dir.join("dir/t4.txt"))?, "dir test");
    Ok(())
}

#[test]
fn test_encrypt_multiple_times() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    fs::create_dir(temp_dir.join("dir"))?;
    fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt multiple times
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{x:?}"));
    temp_dir
        .join("dir")
        .read_dir()?
        .for_each(|x| println!("{x:?}"));
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    // Decrypt
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test

    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_not_encrypted());
    assert_eq!(
        fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(fs::read_to_string(temp_dir.join("dir/t4.txt"))?, "dir test");

    Ok(())
}

#[test]
#[ignore = "This test takes too long to run, and it's not necessary to run it every time. You can \
            run it manually if you want."]
fn test_many_files() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let dir = temp_dir.join("dir");
    fs::create_dir(&dir)?;
    let files = (1..2000)
        .map(|i| {
            dir.join(format!("file{i}.txt"))
                .tap(|f| fs::write(f, "Hello").unwrap())
        })
        .collect::<Vec<PathBuf>>();

    // Add file
    run(
        SubCommand::Add {
            paths: vec!["dir".into()],
        },
        temp_dir,
    )?;

    // Encrypt
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    // Decrypt
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;

    // Test
    for _ in 1..10 {
        let file_name = files.choose(&mut rand::rng()).unwrap();
        println!("Testing file: {}", file_name.display());
        assert_eq!(fs::read_to_string(file_name)?, "Hello");
    }

    Ok(())
}

#[test]
fn test_large_file_encrypt_decrypt() -> anyhow::Result<()> {
    const FILE_SIZE: usize = 5 * 1024 * 1024; // 5 MB
    let pwd = test_init();
    let temp_dir = pwd.path();

    let mut rng = SmallRng::from_seed([42; 32]);
    let original_data: Vec<u8> = (0..FILE_SIZE).map(|_| rng.random::<u8>()).collect();

    let file_path = temp_dir.join("large.bin");
    fs::write(&file_path, &original_data)?;

    run(
        SubCommand::Add {
            paths: vec![file_path.clone()],
        },
        temp_dir,
    )?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    assert!(file_path.is_encrypted());
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;

    let decrypted_data = fs::read(&file_path)?;
    assert_eq!(decrypted_data, original_data);
    assert!(file_path.is_not_encrypted());

    Ok(())
}

/// Compressed multi-chunk roundtrip: the file's *compressed* stream spans
/// several 64KB chunks. The payload is half random (incompressible, passes
/// through as zstd raw blocks) and half zeros (highly compressible), so the
/// compressed stream stays around 256KB — multiple chunks — while the real
/// decompression path still runs for the zeros. Also locks determinism of the
/// compressed ciphertext: decrypt → encrypt must reproduce the exact bytes.
#[test]
fn test_compressible_multichunk_roundtrip() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let mut rng = SmallRng::from_seed([0xab; 32]);
    let mut original = Vec::with_capacity(512 * 1024);
    original.extend((0..256 * 1024).map(|_| rng.random::<u8>()));
    original.extend(std::iter::repeat_n(0u8, 256 * 1024));

    let file_path = temp_dir.join("mixed.bin");
    fs::write(&file_path, &original)?;

    run(
        SubCommand::Add {
            paths: vec![file_path.clone()],
        },
        temp_dir,
    )?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    assert!(file_path.is_compressed());
    // The compressed stream exceeds one chunk: 64B header + at least two
    // [NONCE (24) | CIPHERTEXT (<= 64KB) | TAG (16)] frames.
    assert!(
        fs::metadata(&file_path)?.len() > u64::try_from(64 + 2 * (24 + 64 * 1024 + 16)).unwrap(),
        "compressed stream should span multiple chunks"
    );
    let ciphertext = fs::read(&file_path)?;

    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    assert_eq!(fs::read(&file_path)?, original);

    // Re-encrypting the unchanged file must reproduce the same compressed
    // ciphertext byte for byte.
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    assert_eq!(fs::read(&file_path)?, ciphertext);

    Ok(())
}

#[test]
fn test_partial_decrypt() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    fs::create_dir(temp_dir.join("dir"))?;
    fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Partial decrypt
    run(
        SubCommand::Decrypt {
            paths: vec!["dir".into()],
        },
        temp_dir,
    )?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("dir/t4.txt").exists());

    // Reencrypt
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Partial decrypt
    run(
        SubCommand::Decrypt {
            paths: vec!["t1.txt".into()],
        },
        temp_dir,
    )?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").exists());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    Ok(())
}

#[test]
fn test_tampered_encrypted_file_fails_aad() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let file_path = temp_dir.join("secret.txt");
    let original_content = b"Hello, this is a secret message that must be authenticated!";
    fs::write(&file_path, original_content)?;

    run(
        SubCommand::Add {
            paths: vec![file_path.clone()],
        },
        temp_dir,
    )?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    assert!(file_path.is_encrypted());
    let mut encrypted_data = fs::read(&file_path)?;
    assert_ne!(encrypted_data, [] as [u8; 0]);

    // 篡改：翻转中间的一个字节
    let mid = encrypted_data.len() / 2;
    encrypted_data[mid] ^= 0xff;

    // 写回篡改后的数据
    fs::write(&file_path, &encrypted_data)?;

    // 尝试解密，应该失败（AAD 校验不通过）
    let decrypt_result = run(SubCommand::Decrypt { paths: vec![] }, temp_dir);
    dbg!(&decrypt_result);
    assert!(decrypt_result.is_err());
    // 可选：验证文件仍然处于加密状态（因为解密失败，文件未被修改）
    assert!(file_path.is_encrypted());

    // 另一种篡改方式：截断文件末尾 10 个字节
    let mut encrypted_data2 = fs::read(&file_path)?;
    encrypted_data2.truncate(encrypted_data2.len().saturating_sub(10));
    fs::write(&file_path, &encrypted_data2)?;

    let decrypt_result2 = run(SubCommand::Decrypt { paths: vec![] }, temp_dir);
    dbg!(&decrypt_result);
    assert!(decrypt_result2.is_err());

    Ok(())
}

#[test]
fn test_deterministic_reencryption() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    fs::create_dir(temp_dir.join("dir"))?;
    fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    fs::write(temp_dir.join("t2.txt"), "6".repeat(100))?;
    fs::write(temp_dir.join("dir/t3.txt"), "nested file")?;

    // Add files
    run(
        SubCommand::Add {
            paths: ["t1.txt", "t2.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // ---- First encrypt ----
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("t2.txt").is_compressed());
    assert!(temp_dir.join("dir/t3.txt").is_encrypted());

    let enc1_t1 = fs::read(temp_dir.join("t1.txt"))?;
    let enc1_t2 = fs::read(temp_dir.join("t2.txt"))?;
    let enc1_t3 = fs::read(temp_dir.join("dir/t3.txt"))?;

    // ---- Decrypt ----
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    assert_eq!(
        fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("dir/t3.txt"))?,
        "nested file"
    );

    // ---- Re-encrypt (should produce identical ciphertext) ----
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    let enc2_t1 = fs::read(temp_dir.join("t1.txt"))?;
    let enc2_t2 = fs::read(temp_dir.join("t2.txt"))?;
    let enc2_t3 = fs::read(temp_dir.join("dir/t3.txt"))?;

    assert_eq!(
        enc1_t1, enc2_t1,
        "t1.txt: decrypt→encrypt must produce identical ciphertext"
    );
    assert_eq!(
        enc1_t2, enc2_t2,
        "t2.txt: decrypt→encrypt must produce identical ciphertext"
    );
    assert_eq!(
        enc1_t3, enc2_t3,
        "dir/t3.txt: decrypt→encrypt must produce identical ciphertext"
    );

    // Verify the files still decrypt correctly
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    assert_eq!(
        fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("dir/t3.txt"))?,
        "nested file"
    );

    Ok(())
}

#[test]
fn test_deterministic_reencryption_multiple_cycles() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    fs::write(temp_dir.join("data.txt"), "persistent data")?;

    run(
        SubCommand::Add {
            paths: vec!["data.txt".into()],
        },
        temp_dir,
    )?;

    // Encrypt and capture ciphertext from 3 decrypt→encrypt cycles
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    let reference = fs::read(temp_dir.join("data.txt"))?;

    for cycle in 1..=3 {
        run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
        assert_eq!(
            fs::read_to_string(temp_dir.join("data.txt"))?,
            "persistent data",
            "Data corrupted at cycle {cycle}"
        );

        run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
        let ciphertext = fs::read(temp_dir.join("data.txt"))?;
        assert_eq!(ciphertext, reference, "Ciphertext changed at cycle {cycle}");
    }

    Ok(())
}

#[test]
fn test_check_staged() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    fs::write(temp_dir.join("encrypted.txt"), "already encrypted")?;
    fs::write(temp_dir.join("unencrypted.txt"), "not yet encrypted")?;
    fs::write(temp_dir.join("plain.txt"), "not in crypt list")?;

    run(
        SubCommand::Add {
            paths: ["encrypted.txt", "unencrypted.txt"]
                .map(PathBuf::from)
                .to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt only encrypted.txt, leave unencrypted.txt as-is
    run(
        SubCommand::Encrypt {
            paths: vec!["encrypted.txt".into()],
        },
        temp_dir,
    )?;
    assert!(temp_dir.join("encrypted.txt").is_encrypted());
    assert!(temp_dir.join("unencrypted.txt").is_not_encrypted());

    // Case 1: stage only the encrypted file → should pass
    exec("git add encrypted.txt", temp_dir).context("git add encrypted.txt")?;
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_ok(),
        "encrypted staged file should pass check"
    );

    // Case 2: also stage the unencrypted file (in crypt list) → should fail
    exec("git add unencrypted.txt", temp_dir).context("git add unencrypted.txt")?;
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_err(),
        "unencrypted staged file (in crypt list) should fail check"
    );

    // Clear index
    exec("git rm --cached encrypted.txt unencrypted.txt", temp_dir).context("git rm --cached")?;

    // Case 3: stage a file not in crypt list → should pass (nothing to check)
    exec("git add plain.txt", temp_dir).context("git add plain.txt")?;
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_ok(),
        "staged file not in crypt list should pass check"
    );

    // Clear index
    exec("git rm --cached plain.txt", temp_dir).context("git rm --cached")?;

    // Case 4: nothing staged → should pass
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_ok(),
        "nothing staged should pass check"
    );

    Ok(())
}

/// Regression test for BUG-1: a staged plaintext file with a non-ASCII name
/// must still be detected under git's default `core.quotepath = true`, where
/// `git diff --name-only` emits C-quoted octal-escaped paths that would
/// otherwise never match a real path and silently skip the check.
#[test]
fn test_check_staged_non_ascii_under_default_git_config() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    // Simulate a default-config user so a machine-global
    // `core.quotepath = false` cannot mask the bug.
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    fs::write(temp_dir.join("密.txt"), "not yet encrypted")?;
    run(
        SubCommand::Add {
            paths: vec!["密.txt".into()],
        },
        temp_dir,
    )?;
    exec("git add 密.txt", temp_dir).context("git add 密.txt")?;

    let result = run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        temp_dir,
    );
    let err = result.expect_err("staged non-ASCII plaintext must fail check");
    let err = err
        .downcast_ref::<git_simple_encrypt::Error>()
        .expect("should be a library error");
    assert!(matches!(
        err,
        git_simple_encrypt::Error::FilesNotEncrypted(1, 1)
    ));

    Ok(())
}

/// Run the real git-se binary in `pwd`. `install` must go through the binary:
/// it records the running executable's path into the filter config, and
/// in-process tests would record the test runner instead.
fn run_bin(pwd: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_git-se"))
        .args(args)
        .current_dir(pwd)
        .output()
        .context("spawn git-se")?;
    anyhow::ensure!(
        out.status.success(),
        "git-se {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run a git command in `pwd`, asserting success and returning stdout.
fn git(pwd: &Path, args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = Command::new("git")
        .args(args)
        .current_dir(pwd)
        .output()
        .with_context(|| format!("git {args:?}"))?;
    anyhow::ensure!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(out.stdout)
}

fn git_str(pwd: &Path, args: &[&str]) -> anyhow::Result<String> {
    Ok(String::from_utf8(git(pwd, args)?)?.trim().to_owned())
}

/// Local identity so commits work without touching the global git config.
fn git_identity(pwd: &Path) -> anyhow::Result<()> {
    git(pwd, &["config", "user.name", "t"])?;
    git(pwd, &["config", "user.email", "t@t"])?;
    Ok(())
}

/// Full filter-mode lifecycle: install, transparent add (encrypt), checkout
/// (decrypt), plaintext diff, deterministic re-clean, plaintext-blob migration
/// via `git add --renormalize`.
#[test]
fn test_filter_install_roundtrip() -> anyhow::Result<()> {
    // Content assertions after `git checkout` require a default-config user:
    // a global `core.autocrlf` would rewrite every checked-out file.
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    let pwd = bench_init();
    let dir = pwd.path();
    git_identity(dir)?;

    fs::write(
        dir.join("secret.txt"),
        "top secret
",
    )?;
    fs::create_dir(dir.join("sub"))?;
    fs::write(
        dir.join("sub/nested.txt"),
        "nested secret
",
    )?;
    run(
        SubCommand::Add {
            paths: ["secret.txt", "sub"].map(PathBuf::from).to_vec(),
        },
        dir,
    )?;

    // commit a plaintext blob before the filter exists (pre-migration state)
    git(dir, &["add", "secret.txt"])?;
    git(dir, &["commit", "-m", "plain"])?;

    let out = run_bin(dir, &["install"])?;
    assert!(
        out.contains("renormalize"),
        "expected a renormalize hint for plaintext blobs, got: {out}"
    );

    // managed .gitattributes: directory entries cascade via a /** suffix
    let attrs = fs::read_to_string(dir.join(".gitattributes"))?;
    assert!(
        attrs.contains("secret.txt filter=git-se diff=git-se"),
        "{attrs}"
    );
    assert!(
        attrs.contains("sub/** filter=git-se diff=git-se"),
        "{attrs}"
    );

    // filter driver config
    assert_eq!(
        git_str(dir, &[
            "config",
            "--local",
            "--get",
            "filter.git-se.required"
        ])?,
        "true"
    );

    // smudge passes plaintext blobs through untouched
    assert_eq!(
        String::from_utf8(git(dir, &["cat-file", "--filters", ":secret.txt"])?)?,
        "top secret
"
    );

    // `git add` encrypts; the worktree stays plaintext
    git(dir, &["add", "sub/nested.txt"])?;
    assert!(git(dir, &["cat-file", "blob", ":sub/nested.txt"])?.starts_with(b"GITSE"));
    assert_eq!(
        fs::read_to_string(dir.join("sub/nested.txt"))?,
        "nested secret
"
    );

    // renormalize re-stages the old plaintext blob as ciphertext
    git(dir, &["add", "--renormalize", "."])?;
    assert!(git(dir, &["cat-file", "blob", ":secret.txt"])?.starts_with(b"GITSE"));

    // deterministic: re-cleaning produces the same blob oid
    let oid1 = git_str(dir, &["rev-parse", ":sub/nested.txt"])?;
    git(dir, &["add", "--renormalize", "."])?;
    let oid2 = git_str(dir, &["rev-parse", ":sub/nested.txt"])?;
    assert_eq!(oid1, oid2, "re-clean must be deterministic");

    git(dir, &["commit", "-m", "enc"])?;

    // checkout smudges back to plaintext
    fs::remove_file(dir.join("secret.txt"))?;
    git(dir, &["checkout", "--", "secret.txt"])?;
    assert_eq!(
        fs::read_to_string(dir.join("secret.txt"))?,
        "top secret
"
    );

    // `git diff` shows plaintext on both sides, never ciphertext
    fs::write(
        dir.join("secret.txt"),
        "changed secret
",
    )?;
    let diff = String::from_utf8(git(dir, &["diff", "--", "secret.txt"])?)?;
    assert!(diff.contains("-top secret"), "{diff}");
    assert!(diff.contains("+changed secret"), "{diff}");
    assert!(!diff.contains("GITSE"), "{diff}");

    Ok(())
}

/// Fresh clone + install: the tracked ciphertext worktree is decrypted
/// automatically (force re-checkout) and re-adding reproduces the exact
/// committed blobs.
#[test]
fn test_filter_install_on_clone() -> anyhow::Result<()> {
    // The clone and the install-time re-checkout are both subject to a global
    // `core.autocrlf`; the exact-content assertions need a default-config user.
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    // origin repo with committed ciphertext
    let origin = bench_init();
    let odir = origin.path();
    git_identity(odir)?;
    fs::create_dir(odir.join("sub"))?;
    fs::write(
        odir.join("secret.txt"),
        "top secret
",
    )?;
    fs::write(
        odir.join("sub/nested.txt"),
        "nested secret
",
    )?;
    run(
        SubCommand::Add {
            paths: ["secret.txt", "sub"].map(PathBuf::from).to_vec(),
        },
        odir,
    )?;
    run_bin(odir, &["install"])?;
    git(odir, &["add", "."])?;
    git(odir, &["commit", "-m", "enc"])?;

    // clone: worktree holds raw ciphertext, filter config is local-only
    let clone_parent = TempDir::new()?;
    let cdir = clone_parent.path().join("clone");
    git(clone_parent.path(), &[
        "clone",
        &odir.display().to_string(),
        "clone",
    ])?;
    assert!(fs::read(cdir.join("secret.txt"))?.starts_with(b"GITSE"));

    // install decrypts the worktree automatically
    run(
        SubCommand::Set {
            field: SetField::Key {
                value: "12345678910987654321".to_owned(),
            },
        },
        &cdir,
    )?;
    let out = run_bin(&cdir, &["install"])?;
    assert!(
        out.contains("Auto decrypted 2 tracked file(s)"),
        "expected auto decryption, got: {out}"
    );
    assert_eq!(
        fs::read_to_string(cdir.join("secret.txt"))?,
        "top secret
"
    );
    assert_eq!(
        fs::read_to_string(cdir.join("sub/nested.txt"))?,
        "nested secret
"
    );

    // nothing dirty: status is clean right after install
    assert_eq!(git_str(&cdir, &["status", "--porcelain"])?, "");

    // re-adding the plaintext worktree reproduces the committed blobs
    git(&cdir, &["add", "."])?;
    assert_eq!(
        git_str(&cdir, &["rev-parse", "HEAD:secret.txt"])?,
        git_str(&cdir, &["rev-parse", ":secret.txt"])?,
        "clean must reproduce the committed ciphertext"
    );
    assert_eq!(git_str(&cdir, &["status", "--porcelain"])?, "");

    Ok(())
}

/// Hook-only install keeps the legacy behavior; a filter install afterwards
/// removes the managed hook (it would reject the intentionally plaintext
/// worktree).
#[test]
fn test_hook_mode_and_filter_migration() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();
    fs::write(
        dir.join("s.txt"),
        "secret
",
    )?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        dir,
    )?;

    run_bin(dir, &["install", "--mode", "hook"])?;
    assert!(dir.join(".git/hooks/pre-commit").exists());
    assert!(!dir.join(".gitattributes").exists());
    assert!(
        git(dir, &["config", "--local", "--get", "filter.git-se.clean"]).is_err(),
        "hook mode must not configure the filter driver"
    );

    run_bin(dir, &["install"])?;
    assert!(!dir.join(".git/hooks/pre-commit").exists());
    assert!(dir.join(".gitattributes").exists());
    assert!(
        git_str(dir, &["config", "--local", "--get", "filter.git-se.clean"])?.contains("clean %f")
    );

    Ok(())
}

/// Paths with spaces (and a directory with a space) must land in
/// `.gitattributes` as C-quoted patterns and actually match: `git add`
/// encrypts them instead of silently dropping the line.
#[test]
fn test_filter_paths_with_spaces() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();
    git_identity(dir)?;

    fs::create_dir(dir.join("my dir"))?;
    fs::write(dir.join("my dir/inner.txt"), "nested secret\n")?;
    fs::write(dir.join("a file.txt"), "spaced secret\n")?;
    run(
        SubCommand::Add {
            paths: ["my dir", "a file.txt"].map(PathBuf::from).to_vec(),
        },
        dir,
    )?;
    run_bin(dir, &["install"])?;

    let attrs = fs::read_to_string(dir.join(".gitattributes"))?;
    assert!(
        attrs.contains("\"a file.txt\" filter=git-se diff=git-se"),
        "{attrs}"
    );
    assert!(
        attrs.contains("\"my dir/**\" filter=git-se diff=git-se"),
        "{attrs}"
    );

    // the quoted patterns actually drive the filter
    git(dir, &["add", "."])?;
    assert!(git(dir, &["cat-file", "blob", ":a file.txt"])?.starts_with(b"GITSE"));
    assert!(git(dir, &["cat-file", "blob", ":my dir/inner.txt"])?.starts_with(b"GITSE"));

    Ok(())
}

/// In filter mode, plain `check` is a no-op, but `check --staged` inspects
/// the staged blobs: a clean-filtered (encrypted) blob passes, while a blob
/// staged with the filter bypassed (`git add --no-filters`... simulated via
/// `hash-object -w --no-filters` + `update-index`) fails the check.
#[test]
fn test_check_staged_in_filter_mode() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();
    git_identity(dir)?;

    fs::write(dir.join("s.txt"), "secret\n")?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        dir,
    )?;
    run_bin(dir, &["install"])?;

    // staged through the clean filter: ciphertext blob -> check passes
    git(dir, &["add", "s.txt"])?;
    run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        dir,
    )?;

    // bypass the filter and stage the raw plaintext blob -> check fails
    let oid = git_str(dir, &["hash-object", "-w", "--no-filters", "s.txt"])?;
    git(dir, &[
        "update-index",
        "--cacheinfo",
        &format!("100644,{oid},s.txt"),
    ])?;
    let result = run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        dir,
    );
    assert!(result.is_err(), "plaintext staged blob must fail the check");

    Ok(())
}

// ============ region config / walker / escape ============

/// `e .` must encrypt the working tree but never descend into `.git` —
/// encrypting git metadata would brick the repository and break the
/// recovery path (`d .` needs `.git/config` for the password).
#[test]
fn walker_encrypt_root_dot_skips_git_dir() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();
    fs::write(temp_dir.join("plain.txt"), "data")?;
    assert!(temp_dir.join(".git").join("HEAD").is_file());

    run(
        SubCommand::Encrypt {
            paths: vec![".".into()],
        },
        temp_dir,
    )?;
    assert!(temp_dir.join("plain.txt").is_encrypted());
    assert!(temp_dir.join(".git").join("HEAD").is_not_encrypted());
    assert!(temp_dir.join(".git").join("config").is_not_encrypted());

    // Recovery still works: `d .` decrypts the worktree only.
    run(
        SubCommand::Decrypt {
            paths: vec![".".into()],
        },
        temp_dir,
    )?;
    assert_eq!(fs::read_to_string(temp_dir.join("plain.txt"))?, "data");
    Ok(())
}

/// `add` rejects entries that would corrupt or escape the repository: the
/// repo root (`.`/`./`/absolute), `.git` internals and `..`-escapes. The
/// config file must stay untouched.
#[test]
fn config_add_rejects_repo_root_git_and_escapes() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();
    fs::write(temp_dir.join("f.txt"), "x")?;

    for bad in [
        ".".to_string(),
        "./".to_string(),
        temp_dir.display().to_string(),
    ] {
        let result = run(
            SubCommand::Add {
                paths: vec![bad.clone().into()],
            },
            temp_dir,
        );
        assert!(result.is_err(), "add {bad} must be rejected");
    }
    assert!(!temp_dir.join("git_simple_encrypt.toml").exists());

    // A sibling directory reached via `..` is an escape.
    let outside = TempDir::new()?;
    let name = outside.path().file_name().unwrap().to_owned();
    let relative_escape = PathBuf::from("..").join(&name);
    let err = run(
        SubCommand::Add {
            paths: vec![relative_escape],
        },
        temp_dir,
    )
    .expect_err("relative escape must be rejected");
    let err = err
        .downcast_ref::<git_simple_encrypt::Error>()
        .expect("should be a library error");
    assert!(matches!(err, git_simple_encrypt::Error::PathNotRelative(_)));

    // An absolute path outside the repo is rejected the same way.
    let err = run(
        SubCommand::Add {
            paths: vec![outside.path().to_path_buf()],
        },
        temp_dir,
    )
    .expect_err("absolute outside path must be rejected");
    let err = err
        .downcast_ref::<git_simple_encrypt::Error>()
        .expect("should be a library error");
    assert!(matches!(err, git_simple_encrypt::Error::PathNotRelative(_)));

    assert!(!temp_dir.join("git_simple_encrypt.toml").exists());
    Ok(())
}

/// Encrypt/decrypt must never touch files outside the repository, whether
/// the escaping path is relative (`..`) or absolute.
#[test]
fn escape_encrypt_outside_paths_are_skipped() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let outside = TempDir::new()?;
    let absolute_target = outside.path().join("secret.txt");
    fs::write(&absolute_target, "outside secret")?;
    let name = outside.path().file_name().unwrap().to_owned();
    let relative_target = PathBuf::from("..").join(&name).join("secret.txt");

    for escaping in [absolute_target.clone(), relative_target] {
        let result = run(
            SubCommand::Encrypt {
                paths: vec![escaping],
            },
            temp_dir,
        );
        assert!(result.is_err(), "encrypting outside the repo must fail");
    }
    assert!(
        fs::read_to_string(&absolute_target)? == "outside secret",
        "the outside file must stay untouched"
    );
    Ok(())
}

/// Absolute paths inside the repository are first-class targets: they used
/// to panic on debug builds (`debug_assert`) while release builds handled
/// them via `Path::join` replacement semantics.
#[test]
fn walker_absolute_path_roundtrip() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();
    let file = temp_dir.join("abs.txt");
    assert!(file.is_absolute());
    fs::write(&file, "absolute path content")?;

    run(
        SubCommand::Encrypt {
            paths: vec![file.clone()],
        },
        temp_dir,
    )?;
    assert!(file.is_encrypted());

    run(
        SubCommand::Decrypt {
            paths: vec![file.clone()],
        },
        temp_dir,
    )?;
    assert_eq!(fs::read_to_string(&file)?, "absolute path content");
    Ok(())
}

/// Files inside crypt-list entries that the ignore rules exclude must not be
/// silently skipped: `e` does not encrypt them, but it (and `check`) warns
/// loudly — otherwise they form a silent hole in the pre-commit defense.
#[test]
fn walker_ignored_file_in_crypt_entry_warns() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();
    fs::write(temp_dir.join(".gitignore"), "*.env\n")?;
    fs::create_dir(temp_dir.join("dir"))?;
    fs::write(temp_dir.join("dir").join("keep.txt"), "keep")?;
    fs::write(temp_dir.join("dir").join("x.env"), "secret")?;
    // An ignored file OUTSIDE crypt coverage: plain ignore semantics, no
    // warning expected.
    fs::create_dir(temp_dir.join("otherdir"))?;
    fs::write(temp_dir.join("otherdir").join("y.env"), "unrelated")?;

    run(
        SubCommand::Add {
            paths: vec!["dir".into()],
        },
        temp_dir,
    )?;

    // List-mode `e`: keep.txt encrypted, x.env excluded but warned about.
    let out = run_bin(temp_dir, &["e"])?;
    assert!(
        out.contains("x.env"),
        "warning must surface on stdout: {out}"
    );
    assert!(
        !out.contains("otherdir"),
        "no warning for files outside crypt coverage: {out}"
    );
    assert!(temp_dir.join("dir").join("keep.txt").is_encrypted());
    assert!(temp_dir.join("dir").join("x.env").is_not_encrypted());

    // `check` surfaces the same warning (the file is invisible to it).
    let out = run_bin(temp_dir, &["c"])?;
    assert!(out.contains("x.env"), "{out}");

    // Explicit-path `e dir` (inside crypt coverage) warns as well.
    let out = run_bin(temp_dir, &["e", "dir"])?;
    assert!(out.contains("x.env"), "{out}");
    Ok(())
}

// ============ region: git integration & password hardening (repo.rs batch) ============

/// Linked worktree (`git worktree add`): the `.git` entry is a `gitdir:`
/// pointer file. The salt cache must resolve through it to the worktree's
/// private gitdir, or every clean mints a fresh salt and re-adds drift
/// (the blob oid changes on each re-clean).
#[test]
fn worktree_filter_add_is_deterministic() -> anyhow::Result<()> {
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    let pwd = bench_init();
    let dir = pwd.path();
    git_identity(dir)?;
    fs::write(dir.join("s.txt"), "secret\n")?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        dir,
    )?;
    run_bin(dir, &["install"])?;
    git(dir, &["add", "."])?;
    git(dir, &["commit", "-m", "init"])?;

    let wt_parent = TempDir::new()?;
    let wtdir = wt_parent.path().join("wt");
    git(dir, &["worktree", "add", &wtdir.display().to_string()])?;
    assert!(
        wtdir.join(".git").is_file(),
        "linked worktree .git must be a pointer file"
    );

    fs::write(wtdir.join("new.txt"), "fresh secret\n")?;
    git(&wtdir, &["add", "new.txt"])?;
    let oid1 = git_str(&wtdir, &["rev-parse", ":new.txt"])?;

    // Force a re-clean (a plain re-add would be skipped by the stat cache).
    git(&wtdir, &["add", "--renormalize", "."])?;
    let oid2 = git_str(&wtdir, &["rev-parse", ":new.txt"])?;
    assert_eq!(
        oid1, oid2,
        "clean in a linked worktree must be deterministic"
    );

    // The cache lives under the worktree's real gitdir, not beside the pointer.
    let cache = dir
        .join(".git")
        .join("worktrees")
        .join("wt")
        .join("git-simple-encrypt-salt-cache");
    assert!(
        cache.is_file(),
        "salt cache expected at {}",
        cache.display()
    );
    Ok(())
}

/// A repo-local `core.hooksPath` (relative, resolved against the worktree
/// root) decides where the hook is installed; `.git/hooks` is not written.
#[test]
fn hook_respects_local_core_hookspath() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();
    git(dir, &["config", "--local", "core.hooksPath", "my-hooks"])?;
    run_bin(dir, &["install", "--mode", "hook"])?;

    let hook = dir.join("my-hooks").join("pre-commit");
    assert!(hook.is_file(), "hook expected at {}", hook.display());
    assert!(!dir.join(".git").join("hooks").join("pre-commit").exists());
    Ok(())
}

/// The hook template must invoke the installing binary by absolute path —
/// a bare `git-se` depends on PATH and blocks commits in GUI clients/CI.
#[test]
fn hook_invokes_absolute_exe_path() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();
    run_bin(dir, &["install", "--mode", "hook"])?;

    let hook = dir.join(".git").join("hooks").join("pre-commit");
    let content = fs::read_to_string(&hook)?;
    let exe = env!("CARGO_BIN_EXE_git-se").replace('\\', "/");
    assert!(
        content.contains(&format!("'{exe}' check --staged")),
        "hook should call the absolute exe path, got: {content}"
    );
    Ok(())
}

/// `e`/`c`/`d` invoked with the repo argument pointing at a subdirectory
/// must discover the repo root and act on repo-relative targets.
#[test]
fn subdir_encrypt_check_decrypt() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();
    fs::create_dir(dir.join("sub"))?;
    fs::write(dir.join("sub/s.txt"), "secret\n")?;
    run(
        SubCommand::Add {
            paths: vec!["sub".into()],
        },
        dir,
    )?;

    let sub = dir.join("sub");
    run(SubCommand::Encrypt { paths: vec![] }, &sub)?;
    assert!(dir.join("sub/s.txt").is_encrypted());
    run(
        SubCommand::Check {
            paths: vec![],
            staged: false,
        },
        &sub,
    )?;
    run(SubCommand::Decrypt { paths: vec![] }, &sub)?;
    assert_eq!(fs::read_to_string(dir.join("sub/s.txt"))?, "secret\n");
    Ok(())
}

/// Staged files whose names contain spaces, non-ASCII (and quotes /
/// backslashes on unix) must be enumerated and checked byte-exactly: the
/// staged enumeration uses `-z`, so git's C-quoting cannot hide them.
#[test]
fn stagedblob_special_char_paths_are_checked() -> anyhow::Result<()> {
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    let pwd = test_init();
    let dir = pwd.path();

    // `mut` is only consumed by the unix-only quote/backslash additions.
    #[allow(unused_mut)]
    let mut names: Vec<String> = vec![
        "sp ace.txt".to_string(),
        "dir with space/inner file.txt".to_string(),
        "密码文件.txt".to_string(),
    ];
    // `"` and `\` are legal filename bytes on unix only (Windows forbids them).
    #[cfg(unix)]
    names.extend(["quo\"te.txt".to_string(), "back\\slash.txt".to_string()]);

    for name in &names {
        if let Some(parent) = Path::new(name)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            fs::create_dir_all(dir.join(parent))?;
        }
        fs::write(dir.join(name), "plaintext\n")?;
    }
    run(
        SubCommand::Add {
            paths: names.iter().map(PathBuf::from).collect(),
        },
        dir,
    )?;

    let mut add_args: Vec<&str> = vec!["add", "--"];
    add_args.extend(names.iter().map(String::as_str));
    git(dir, &add_args)?;

    let result = run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        dir,
    );
    let err = result.expect_err("staged plaintext with special-char names must fail");
    let err = err
        .downcast_ref::<git_simple_encrypt::Error>()
        .expect("should be a library error");
    let expected = names.len();
    assert!(
        matches!(err, git_simple_encrypt::Error::FilesNotEncrypted(n, t) if *n == expected && *t == expected),
        "expected all {expected} files flagged, got: {err:?}"
    );

    // After encrypting and re-staging, the blobs are ciphertext and pass.
    run(SubCommand::Encrypt { paths: vec![] }, dir)?;
    git(dir, &add_args)?;
    run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        dir,
    )?;
    Ok(())
}

/// A staged file whose worktree copy was deleted afterwards must still be
/// checked — the staged blob is what the commit would write. An `exists()`
/// filter used to drop such files, letting plaintext through the hook.
#[test]
fn stagedblob_worktree_deleted_file_is_still_checked() -> anyhow::Result<()> {
    let pwd = test_init();
    let dir = pwd.path();

    fs::write(dir.join("gone.txt"), "plaintext\n")?;
    run(
        SubCommand::Add {
            paths: vec!["gone.txt".into()],
        },
        dir,
    )?;
    git(dir, &["add", "gone.txt"])?;
    fs::remove_file(dir.join("gone.txt"))?;

    let result = run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        dir,
    );
    let err = result.expect_err("staged plaintext without a worktree copy must fail");
    let err = err
        .downcast_ref::<git_simple_encrypt::Error>()
        .expect("should be a library error");
    assert!(
        matches!(err, git_simple_encrypt::Error::FilesNotEncrypted(1, 1)),
        "got: {err:?}"
    );
    Ok(())
}

/// Staged plaintext cannot be masked by an encrypted worktree: the check
/// inspects the staged blob, not the file on disk.
#[test]
fn stagedblob_encrypted_worktree_cannot_mask_staged_plaintext() -> anyhow::Result<()> {
    let pwd = test_init();
    let dir = pwd.path();

    fs::write(dir.join("s.txt"), "plaintext\n")?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        dir,
    )?;
    git(dir, &["add", "s.txt"])?; // stages the plaintext bytes
    run(SubCommand::Encrypt { paths: vec![] }, dir)?; // worktree now ciphertext
    assert!(dir.join("s.txt").is_encrypted());

    let result = run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        dir,
    );
    let err = result.expect_err("staged plaintext blob must fail despite the encrypted worktree");
    let err = err
        .downcast_ref::<git_simple_encrypt::Error>()
        .expect("should be a library error");
    assert!(
        matches!(err, git_simple_encrypt::Error::FilesNotEncrypted(1, 1)),
        "got: {err:?}"
    );
    Ok(())
}

/// `git-se i` must refuse to run its migration checkout over user-staged
/// changes (`git checkout --force HEAD --` resets the index as well) and
/// leave the repository untouched when refusing.
#[test]
fn installguard_refuses_to_reset_staged_changes() -> anyhow::Result<()> {
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    let pwd = bench_init();
    let dir = pwd.path();
    git_identity(dir)?;

    // Commit an encrypted blob in manual mode: afterwards worktree == HEAD
    // blob, exactly the state the install migration force-checkouts.
    fs::write(dir.join("s.txt"), "secret\n")?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        dir,
    )?;
    run(SubCommand::Encrypt { paths: vec![] }, dir)?;
    git(dir, &["add", "s.txt"])?;
    git(dir, &["commit", "-m", "enc"])?;

    // Stage a modification, then restore the worktree to the committed
    // bytes: index != HEAD, worktree == HEAD.
    let committed = fs::read(dir.join("s.txt"))?;
    let mut modified = committed.clone();
    modified.extend_from_slice(b"more");
    fs::write(dir.join("s.txt"), &modified)?;
    git(dir, &["add", "s.txt"])?;
    fs::write(dir.join("s.txt"), &committed)?;

    let out = Command::new(env!("CARGO_BIN_EXE_git-se"))
        .args(["install"])
        .current_dir(dir)
        .output()
        .context("spawn git-se install")?;
    assert!(
        !out.status.success(),
        "install must fail instead of silently discarding staged changes"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("staged"), "unexpected error: {stderr}");

    // The refusal left everything intact.
    assert_eq!(git_str(dir, &["diff", "--cached", "--name-only"])?, "s.txt");
    assert!(git(dir, &["config", "--local", "--get", "filter.git-se.clean"]).is_err());
    assert!(!dir.join(".gitattributes").exists());
    Ok(())
}

/// A stray `git-simple-encrypt.key` in the user's global config must not be
/// adopted: only the repo-local scope is read (matching where `set` writes).
#[test]
fn keyscope_global_config_key_is_not_adopted() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();

    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());
    let global_cfg = empty_home.path().join("gitconfig");
    fs::write(&global_cfg, "[git-simple-encrypt]\n\tkey = global-leak\n")?;
    // SAFETY: restored by the IsolatedGitConfig guard's Drop (the variable
    // was unset when the guard captured it); only git subprocesses of this
    // test observe the temporary value.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("GIT_CONFIG_GLOBAL", &global_cfg);
    }

    git(dir, &[
        "config",
        "--local",
        "--unset",
        "git-simple-encrypt.key",
    ])?;
    fs::write(dir.join("s.txt"), "secret\n")?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        dir,
    )?;
    let err = run(SubCommand::Encrypt { paths: vec![] }, dir)
        .expect_err("encrypt must fail without a repo-local key");
    assert!(
        err.to_string().contains("Key not found"),
        "expected a key-not-found error, got: {err}"
    );

    // A local key wins over the global one.
    run(
        SubCommand::Set {
            field: SetField::Key {
                value: "local-key".to_owned(),
            },
        },
        dir,
    )?;
    assert_eq!(
        git_str(dir, &[
            "config",
            "--local",
            "--get",
            "git-simple-encrypt.key"
        ])?,
        "local-key"
    );
    Ok(())
}

// ============ region: process filter (git >= 2.16) ============

/// Minimal pkt-line helpers for driving the real `git-se filter-process`
/// binary the way git would.
mod pkt {
    use std::io::Read;

    pub const FLUSH: &[u8] = b"0000";

    pub fn line(line: &str) -> Vec<u8> {
        data(format!("{line}\n").as_bytes())
    }

    pub fn data(bytes: &[u8]) -> Vec<u8> {
        let mut v = format!("{:04x}", bytes.len() + 4).into_bytes();
        v.extend_from_slice(bytes);
        v
    }

    pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum Pkt {
        Flush,
        Data(Vec<u8>),
    }

    pub fn read(reader: &mut dyn Read) -> std::io::Result<Pkt> {
        let mut prefix = [0u8; 4];
        reader.read_exact(&mut prefix)?;
        if prefix == *FLUSH {
            return Ok(Pkt::Flush);
        }
        let len = usize::from_str_radix(&String::from_utf8_lossy(&prefix), 16)
            .map_err(std::io::Error::other)?;
        let mut payload = vec![0u8; len - 4];
        reader.read_exact(&mut payload)?;
        Ok(Pkt::Data(payload))
    }

    /// A key=value list terminated by flush.
    pub fn read_list(reader: &mut dyn Read) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            match read(reader).unwrap() {
                Pkt::Flush => return out,
                Pkt::Data(bytes) => {
                    out.push(String::from_utf8_lossy(&bytes).trim_end().to_owned());
                },
            }
        }
    }

    pub fn read_content(reader: &mut dyn Read) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            match read(reader).unwrap() {
                Pkt::Flush => return out,
                Pkt::Data(bytes) => out.extend_from_slice(&bytes),
            }
        }
    }
}

/// Drive the real binary over its stdin/stdout pipes: handshake, one clean,
/// then close stdin (EOF) and read everything it wrote back. Strict parsing
/// doubles as the no-stray-stdout-bytes check: anything non-protocol fails
/// to decode, and nothing may remain after the parsed session.
#[test]
fn filter_process_binary_speaks_pure_protocol() -> anyhow::Result<()> {
    use std::{
        io::{Read as _, Write as _},
        process::{Command, Stdio},
    };

    let pwd = bench_init();
    let dir = pwd.path();

    let mut child = Command::new(env!("CARGO_BIN_EXE_git-se"))
        .args(["filter-process"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // stdout is the protocol channel; stderr may only see the
        // error-level logger, which stays silent on success
        .stderr(Stdio::null())
        .spawn()
        .context("spawn git-se filter-process")?;
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(&pkt::concat(&[
            &pkt::line("git-filter-client"),
            &pkt::line("version=2"),
            pkt::FLUSH,
            &pkt::line("capability=clean"),
            &pkt::line("capability=smudge"),
            pkt::FLUSH,
        ]))?;
        stdin.write_all(&pkt::concat(&[
            &pkt::line("command=clean"),
            &pkt::line("pathname=a.txt"),
            pkt::FLUSH,
            &pkt::data(b"binary protocol session"),
            pkt::FLUSH,
        ]))?;
    }
    drop(child.stdin.take()); // EOF: the process must exit on its own

    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out)?;
    let status = child.wait()?;
    assert!(status.success(), "clean EOF exit expected, got {status}");

    let mut cur = std::io::Cursor::new(&out);
    assert_eq!(pkt::read_list(&mut cur), [
        "git-filter-server".to_string(),
        "version=2".to_string()
    ]);
    assert_eq!(pkt::read_list(&mut cur), [
        "capability=clean".to_string(),
        "capability=smudge".to_string()
    ]);
    assert_eq!(pkt::read_list(&mut cur), ["status=success".to_string()]);
    let ciphertext = pkt::read_content(&mut cur);
    assert!(ciphertext.starts_with(b"GITSE"));
    assert_eq!(pkt::read_list(&mut cur), Vec::<String>::new()); // keep success
    assert_eq!(
        usize::try_from(cur.position()).unwrap(),
        out.len(),
        "stray stdout bytes"
    );

    // interop: the one-shot textconv decrypts the process-mode ciphertext
    fs::write(dir.join("probe.enc"), &ciphertext)?;
    let plain = Command::new(env!("CARGO_BIN_EXE_git-se"))
        .args(["diff", "probe.enc"])
        .current_dir(dir)
        .output()
        .context("spawn git-se diff")?;
    assert!(plain.status.success());
    assert_eq!(plain.stdout, b"binary protocol session");
    fs::remove_file(dir.join("probe.enc"))?;
    Ok(())
}

/// Install wires the process filter; one `git add` of several files encrypts
/// them all through the single daemon, the blobs decrypt on checkout, and a
/// forced re-clean reproduces the identical blobs (determinism).
#[test]
fn filter_process_install_add_checkout_deterministic() -> anyhow::Result<()> {
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    let pwd = bench_init();
    let dir = pwd.path();
    git_identity(dir)?;

    fs::write(dir.join("a.txt"), "secret a\n")?;
    fs::create_dir(dir.join("sub"))?;
    fs::write(dir.join("sub/b.txt"), "secret b\n")?;
    fs::write(dir.join("sub/c.txt"), "secret c\n")?;
    run(
        SubCommand::Add {
            paths: ["a.txt", "sub"].map(PathBuf::from).to_vec(),
        },
        dir,
    )?;

    run_bin(dir, &["install"])?;

    // the process filter is configured next to the clean/smudge fallback
    let process = git_str(dir, &[
        "config",
        "--local",
        "--get",
        "filter.git-se.process",
    ])?;
    assert!(process.contains("filter-process"), "{process}");

    git(dir, &["add", "."])?;
    for f in ["a.txt", "sub/b.txt", "sub/c.txt"] {
        assert!(
            git(dir, &["cat-file", "blob", &format!(":{f}")])?.starts_with(b"GITSE"),
            "{f} must be staged as ciphertext"
        );
    }
    // worktree stays plaintext
    assert_eq!(fs::read_to_string(dir.join("a.txt"))?, "secret a\n");

    // forced re-clean is byte-stable (touch-equivalent: renormalize defeats
    // the stat cache and re-runs clean on every file)
    let oids_before: Vec<String> = ["a.txt", "sub/b.txt", "sub/c.txt"]
        .iter()
        .map(|f| git_str(dir, &["rev-parse", &format!(":{f}")]))
        .collect::<anyhow::Result<_>>()?;
    git(dir, &["add", "--renormalize", "."])?;
    for (f, before) in ["a.txt", "sub/b.txt", "sub/c.txt"].iter().zip(&oids_before) {
        assert_eq!(
            git_str(dir, &["rev-parse", &format!(":{f}")])?,
            *before,
            "re-clean of {f} must be deterministic"
        );
    }

    git(dir, &["commit", "-m", "enc"])?;
    fs::remove_file(dir.join("a.txt"))?;
    git(dir, &["checkout", "--", "a.txt"])?;
    assert_eq!(fs::read_to_string(dir.join("a.txt"))?, "secret a\n");

    Ok(())
}

/// One `git add` through the process filter mints ONE shared salt for every
/// cache miss of that git operation (single Argon2 derivation via the key
/// cache); the one-shot clean/smudge fallback keeps per-file salts.
#[test]
fn filter_process_shares_batch_salt_per_git_operation() -> anyhow::Result<()> {
    use std::collections::HashSet;

    use git_simple_encrypt::salt_cache::SaltCacheReader;

    let pwd = bench_init();
    let dir = pwd.path();

    for i in 0..4 {
        fs::write(dir.join(format!("m{i}.txt")), format!("secret {i}\n"))?;
    }
    run(
        SubCommand::Add {
            paths: ["m0.txt", "m1.txt", "m2.txt", "m3.txt"]
                .map(PathBuf::from)
                .to_vec(),
        },
        dir,
    )?;
    run_bin(dir, &["install"])?;

    git(dir, &["add", "."])?;

    let reader = SaltCacheReader::load(dir);
    let salts: HashSet<[u8; 16]> = (0..4)
        .map(|i| reader.get(format!("m{i}.txt").as_bytes()).unwrap().salt)
        .collect();
    assert_eq!(salts.len(), 1, "one git add shares one batch salt");

    // fallback mode (process unset): a fresh file gets its own salt
    git(dir, &[
        "config",
        "--local",
        "--unset",
        "filter.git-se.process",
    ])?;
    fs::write(dir.join("m4.txt"), "secret 4\n")?;
    run(
        SubCommand::Add {
            paths: vec!["m4.txt".into()],
        },
        dir,
    )?;
    git(dir, &["add", "m4.txt"])?;
    let reader = SaltCacheReader::load(dir);
    assert!(!salts.contains(&reader.get(b"m4.txt").unwrap().salt));

    Ok(())
}

/// Ciphertext interop between the process filter and the one-shot
/// clean/smudge fallback in both directions: same cache, same format.
#[test]
fn filter_process_interop_with_one_shot_filters() -> anyhow::Result<()> {
    let empty_home = TempDir::new().context("create empty HOME")?;
    let _guard = IsolatedGitConfig::new(empty_home.path());

    let pwd = bench_init();
    let dir = pwd.path();
    git_identity(dir)?;

    fs::write(dir.join("a.txt"), "via process\n")?;
    run(
        SubCommand::Add {
            paths: vec!["a.txt".into()],
        },
        dir,
    )?;
    run_bin(dir, &["install"])?;
    git(dir, &["add", "a.txt"])?;
    let process_oid = git_str(dir, &["rev-parse", ":a.txt"])?;

    // one-shot mode: re-clean must reproduce the process-mode blob
    git(dir, &[
        "config",
        "--local",
        "--unset",
        "filter.git-se.process",
    ])?;
    fs::write(dir.join("b.txt"), "via one-shot\n")?;
    run(
        SubCommand::Add {
            paths: vec!["b.txt".into()],
        },
        dir,
    )?;
    git(dir, &["add", "b.txt"])?;
    git(dir, &["add", "--renormalize", "."])?;
    assert_eq!(
        git_str(dir, &["rev-parse", ":a.txt"])?,
        process_oid,
        "one-shot clean must reproduce the process-filter blob"
    );

    // one-shot smudge decrypts both blobs
    git(dir, &["commit", "-m", "enc"])?;
    fs::remove_file(dir.join("a.txt"))?;
    fs::remove_file(dir.join("b.txt"))?;
    git(dir, &["checkout", "--", "."])?;
    assert_eq!(fs::read_to_string(dir.join("a.txt"))?, "via process\n");
    assert_eq!(fs::read_to_string(dir.join("b.txt"))?, "via one-shot\n");

    // and the process filter smudges one-shot-cleaned blobs back
    let clean_cfg = git_str(dir, &["config", "--local", "--get", "filter.git-se.clean"])?;
    let process_cfg = clean_cfg.replace("clean %f", "filter-process");
    git(dir, &[
        "config",
        "--local",
        "filter.git-se.process",
        &process_cfg,
    ])?;
    fs::remove_file(dir.join("a.txt"))?;
    git(dir, &["checkout", "--", "a.txt"])?;
    assert_eq!(fs::read_to_string(dir.join("a.txt"))?, "via process\n");

    Ok(())
}

/// A pre-process-filter install (clean/smudge only) is upgraded by running
/// install again: the process config is added on top.
#[test]
fn filter_process_upgrade_from_old_install() -> anyhow::Result<()> {
    let pwd = bench_init();
    let dir = pwd.path();

    run_bin(dir, &["install"])?;
    assert!(
        git(dir, &[
            "config",
            "--local",
            "--get",
            "filter.git-se.process"
        ])
        .is_ok()
    );
    git(dir, &[
        "config",
        "--local",
        "--unset",
        "filter.git-se.process",
    ])?;

    run_bin(dir, &["install"])?;
    let process = git_str(dir, &[
        "config",
        "--local",
        "--get",
        "filter.git-se.process",
    ])?;
    assert!(process.contains("filter-process"), "{process}");
    // the fallback entries survived the upgrade
    assert!(
        git_str(dir, &["config", "--local", "--get", "filter.git-se.clean"])?.contains("clean %f")
    );
    Ok(())
}

/// Without a usable key the process filter aborts the session, and git
/// (filter.required=true) fails the whole `git add` instead of staging
/// plaintext.
#[test]
fn filter_process_abort_fails_add_without_key() -> anyhow::Result<()> {
    let pwd = TempDir::new()?;
    let dir = pwd.path();
    exec("git init", dir)?;
    fs::write(dir.join("s.txt"), "secret\n")?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        dir,
    )?;
    // no `git-se p`: the key is deliberately missing
    run_bin(dir, &["install"])?;

    let out = Command::new("git")
        .args(["add", "s.txt"])
        .current_dir(dir)
        .output()
        .context("git add")?;
    assert!(
        !out.status.success(),
        "git add must fail when the filter aborts; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        git(dir, &["rev-parse", ":s.txt"]).is_err(),
        "nothing may be staged"
    );
    Ok(())
}
