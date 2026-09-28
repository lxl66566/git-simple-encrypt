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
/// Simulates a default-config user: empty `HOME`, no XDG config and no system
/// config, so `core.quotepath` falls back to its default `true` even when the
/// machine's global git config sets it to `false` (which would mask BUG-1).
/// Previous values are restored on drop, even on panic.
struct IsolatedGitConfig(Vec<(&'static str, Option<OsString>)>);

impl IsolatedGitConfig {
    fn new(empty_home: &Path) -> Self {
        const KEYS: [&str; 3] = ["HOME", "GIT_CONFIG_NOSYSTEM", "XDG_CONFIG_HOME"];
        let guard = Self(KEYS.iter().map(|&k| (k, env::var_os(k))).collect());
        // SAFETY: the temporary values only affect git subprocesses spawned
        // by tests and are benign for them (git works fine without a global
        // config; no commit is made in tests, so no identity is needed).
        unsafe {
            env::set_var("HOME", empty_home);
            env::set_var("GIT_CONFIG_NOSYSTEM", "1");
            env::remove_var("XDG_CONFIG_HOME");
        }
        guard
    }
}

impl Drop for IsolatedGitConfig {
    fn drop(&mut self) {
        // SAFETY: see `IsolatedGitConfig::new`
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
